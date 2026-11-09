#include "broker_transport.h"
#include "network_broker.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#define CHECK(value) do { if (!(value)) { fprintf(stderr, "%s:%d: %s errno=%d\n", __FILE__, __LINE__, #value, errno); exit(1); } } while (0)
static unsigned int passed;
static unsigned int count_fds(void) {
    DIR *directory = opendir("/proc/self/fd"); CHECK(directory != NULL); unsigned int count = 0U;
    struct dirent *entry; while ((entry = readdir(directory)) != NULL)
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) count++;
    CHECK(closedir(directory) == 0); return count;
}
static void pair(int fds[2]) { CHECK(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, fds) == 0); }
static void close_pair(int fds[2]) { CHECK(close(fds[0]) == 0 && close(fds[1]) == 0); }
static void raw_send(int fd, const void *data, size_t size, const int *rights, size_t count) {
    CHECK(count <= 253U);
    union { struct cmsghdr alignment; unsigned char bytes[CMSG_SPACE(253U * sizeof(int))]; } control;
    memset(&control, 0, sizeof(control));
    struct iovec iov = {.iov_base = (void *)data, .iov_len = size};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1U};
    if (count != 0U) {
        message.msg_control = control.bytes; message.msg_controllen = CMSG_SPACE(count * sizeof(int));
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS; header->cmsg_len = CMSG_LEN(count * sizeof(int));
        memcpy(CMSG_DATA(header), rights, count * sizeof(int));
    }
    CHECK(sendmsg(fd, &message, MSG_NOSIGNAL) == (ssize_t)size);
}
static struct sucrune_response create_reply(void) {
    struct sucrune_response response = {.magic = SUCRUNE_BROKER_MAGIC, .size = 8U,
        .result = (int64_t)(SUCRUNE_NET_TOKEN_PREFIX | UINT64_C(64))};
    sucrune_net_put_u32(response.data, 1U); sucrune_net_put_u32(response.data + 4U, 1U); return response;
}
static void normal_files_and_rights(void) {
    unsigned int before = count_fds(); int channel[2]; pair(channel);
    struct sucrune_request request = {.magic = SUCRUNE_BROKER_MAGIC, .operation = 17U};
    request.args[0] = 1024;
    CHECK(sucrune_broker_send_request(channel[0], &request, 1000) == 0);
    struct sucrune_request received;
    CHECK(sucrune_broker_receive_request(channel[1], &received, 1000) == 0);
    CHECK(memcmp(&request, &received, offsetof(struct sucrune_request, data)) == 0);
    struct sucrune_response response = {.magic = SUCRUNE_BROKER_MAGIC, .size = 2U, .result = 2};
    response.data[0] = '/';
    CHECK(sucrune_broker_send_response(channel[1], request.operation, &response, -1, 1000) == 0);
    struct sucrune_response actual; int received_fd = 99;
    CHECK(sucrune_broker_receive_response(channel[0], request.operation, &actual, &received_fd, 1000) == 0);
    CHECK(received_fd == -1 && actual.result == 2 && actual.size == 2U && actual.data[0] == '/');
    int socket_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP); CHECK(socket_fd >= 0);
    response = create_reply();
    CHECK(sucrune_broker_send_response(channel[1], SUCRUNE_NET_SOCKET, &response, socket_fd, 1000) == 0);
    CHECK(sucrune_broker_receive_response(channel[0], SUCRUNE_NET_SOCKET, &actual, &received_fd, 1000) == 0);
    CHECK(received_fd >= 0 && received_fd != socket_fd && (fcntl(received_fd, F_GETFD) & FD_CLOEXEC) != 0);
    struct stat original, copied; CHECK(fstat(socket_fd, &original) == 0 && fstat(received_fd, &copied) == 0);
    CHECK(original.st_dev == copied.st_dev && original.st_ino == copied.st_ino);
    CHECK(close(received_fd) == 0 && close(socket_fd) == 0); close_pair(channel); CHECK(count_fds() == before); passed++;
}
static void request_rights_and_truncation(void) {
    unsigned int before = count_fds(); int file = open("/dev/null", O_RDONLY | O_CLOEXEC); CHECK(file >= 0);
    for (unsigned int mode = 0U; mode < 4U; mode++) {
        int channel[2]; pair(channel);
        unsigned char bytes[sizeof(struct sucrune_request) + 1U]; memset(bytes, 0, sizeof(bytes));
        struct sucrune_request request = {.magic = SUCRUNE_BROKER_MAGIC, .operation = 17U};
        memcpy(bytes, &request, sizeof(request)); size_t size = offsetof(struct sucrune_request, data);
        int rights[253]; size_t count = mode == 2U ? 253U : 1U;
        for (size_t i = 0U; i < count; i++) rights[i] = file;
        if (mode == 1U) size = sizeof(bytes); /* Payload MSG_TRUNC plus rights. */
        if (mode == 2U || mode == 3U) {
            int yes = 1; CHECK(setsockopt(channel[1], SOL_SOCKET, SO_PASSCRED, &yes, sizeof(yes)) == 0);
            /* 253 rights plus kernel credentials exceeds receiver control
             * capacity; the kernel closes undisclosed rights, parser closes
             * every descriptor that did fit. mode 3 tests unknown credentials. */
        }
        raw_send(channel[0], bytes, size, rights, count);
        struct sucrune_request actual; memset(&actual, 0x37, sizeof(actual));
        CHECK(sucrune_broker_receive_request(channel[1], &actual, 1000) == -EPROTO);
        CHECK(actual.magic == UINT32_C(0x37373737));
        close_pair(channel); CHECK(count_fds() == before + 1U);
    }
    CHECK(close(file) == 0); CHECK(count_fds() == before); passed++;
}
static void malformed_responses_close_every_right(void) {
    unsigned int before = count_fds();
    int internet = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP); CHECK(internet >= 0);
    int file = open("/dev/null", O_RDONLY | O_CLOEXEC); CHECK(file >= 0);
    for (unsigned int mode = 0U; mode < 9U; mode++) {
        int channel[2]; pair(channel); struct sucrune_response response = create_reply();
        uint32_t operation = SUCRUNE_NET_SOCKET; int rights[2] = {internet, internet}; size_t count = 1U;
        size_t size = offsetof(struct sucrune_response, data) + response.size;
        if (mode == 0U) count = 2U; /* Announced one, actually two. */
        if (mode == 1U) count = 0U; /* Announced one, no right. */
        if (mode == 2U) response.result = -EACCES; /* Error cannot carry a right. */
        if (mode == 3U) operation = 17U; /* Ordinary file reply cannot carry it. */
        if (mode == 4U) rights[0] = file; /* Valid frame, wrong descriptor kind. */
        if (mode == 5U) response.result = 3; /* File-like token is not a network token. */
        if (mode == 6U) size--; /* Declared bytes do not match packet. */
        if (mode == 7U) response.data[0] = 2U; /* Unknown network version. */
        raw_send(channel[0], &response, size, rights, count);
        struct sucrune_response actual; memset(&actual, 0x37, sizeof(actual)); int received_fd = 77;
        int error = sucrune_broker_receive_response(channel[1], operation, &actual, mode == 8U ? NULL : &received_fd, 1000);
        if (error != -EPROTO) fprintf(stderr, "Malformed response mode=%u returned %d\n", mode, error);
        CHECK(error == -EPROTO);
        CHECK(actual.magic == UINT32_C(0x37373737)); if (mode != 8U) CHECK(received_fd == -1);
        close_pair(channel); CHECK(count_fds() == before + 2U);
    }
    CHECK(close(internet) == 0 && close(file) == 0); CHECK(count_fds() == before); passed++;
}
static void bounded_wait_and_queued_cleanup(void) {
    unsigned int before = count_fds(); int channel[2]; pair(channel);
    struct sucrune_request request = {.magic = SUCRUNE_BROKER_MAGIC, .operation = 17U};
    struct sucrune_response response;
    struct timespec start, end; CHECK(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
    CHECK(sucrune_broker_exchange(channel[0], &request, &response, NULL, 20) == -ETIMEDOUT);
    CHECK(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
    int64_t elapsed = ((int64_t)end.tv_sec - (int64_t)start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000;
    CHECK(elapsed >= 0 && elapsed < 1500); close_pair(channel);
    pair(channel);
    int socket_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP); CHECK(socket_fd >= 0);
    response = create_reply(); CHECK(sucrune_broker_send_response(channel[0], SUCRUNE_NET_SOCKET, &response, socket_fd, 1000) == 0);
    CHECK(close(socket_fd) == 0); close_pair(channel); /* Queued, never received FD is reclaimed by the kernel. */
    CHECK(count_fds() == before); passed++;
}

/* An admitted UDP or TCP FD can still belong to the wrong request. Queue a
 * syntactically valid response from the peer before issuing the exchange so
 * the request-specific type check is exercised without another test thread. */
static void reject_swapped_socket_types(void) {
    unsigned int before = count_fds();
    const int types[] = {SOCK_DGRAM, SOCK_STREAM};
    const int protocols[] = {IPPROTO_UDP, IPPROTO_TCP};
    for (unsigned int i = 0U; i < 2U; i++) {
        unsigned int other = 1U - i;
        int channel[2];
        pair(channel);
        int wrong = socket(AF_INET, types[other] | SOCK_NONBLOCK | SOCK_CLOEXEC, protocols[other]);
        CHECK(wrong >= 0);
        struct sucrune_response malicious = create_reply();
        raw_send(channel[1], &malicious, offsetof(struct sucrune_response, data) + malicious.size, &wrong, 1U);
        struct sucrune_request request = {.magic = SUCRUNE_BROKER_MAGIC, .operation = SUCRUNE_NET_SOCKET,
            .args = {AF_INET, types[i] | SOCK_NONBLOCK, protocols[i], SUCRUNE_NET_VERSION}};
        struct sucrune_response received;
        memset(&received, 0xa5, sizeof(received));
        int right = 53;
        CHECK(sucrune_broker_exchange(channel[0], &request, &received, &right, 1000) == -EPROTO);
        CHECK(right == -1 && received.magic == UINT32_C(0xa5a5a5a5));
        CHECK(fcntl(wrong, F_GETFD) >= 0); /* Sender still owns its original. */
        CHECK(close(wrong) == 0);
        close_pair(channel);
        CHECK(count_fds() == before);
    }
    passed++;
}
static void optional_read_replies(void) {
    unsigned int before = count_fds();
    const char *tmp = getenv("TMPDIR");
    char path[1024];
    int length = snprintf(path, sizeof(path), "%s/sucrune-read-right-XXXXXX", tmp == NULL ? "/tmp" : tmp);
    CHECK(length > 0 && (size_t)length < sizeof(path));
    int writable = mkstemp(path);
    CHECK(writable >= 0);
    int readonly = open(path, O_RDONLY | O_CLOEXEC);
    int path_only = open(path, O_PATH | O_CLOEXEC);
    int dir = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(readonly >= 0 && path_only >= 0 && dir >= 0 && unlink(path) == 0);
    struct sucrune_response answer = {.magic=SUCRUNE_BROKER_MAGIC, .result=3};
    struct sucrune_response received;
    size_t bytes = offsetof(struct sucrune_response, data);
    int right, channel[2];
    const int wrong[] = {writable, path_only, dir};
    for (size_t i = 0; i < sizeof(wrong) / sizeof(wrong[0]); i++) {
        pair(channel);
        raw_send(channel[0], &answer, bytes, &wrong[i], 1);
        CHECK(sucrune_broker_receive_response(channel[1],SUCRUNE_BROKER_OPEN_READ,&received,&right,1000) == -EPROTO);
        CHECK(right == -1);
        close_pair(channel);
    }
    pair(channel);
    int two[] = {readonly, readonly};
    raw_send(channel[0], &answer, bytes, two, 2);
    CHECK(sucrune_broker_receive_response(channel[1],SUCRUNE_BROKER_OPEN_READ,&received,&right,1000) == -EPROTO);
    CHECK(right == -1);
    close_pair(channel);
    pair(channel);
    CHECK(sucrune_broker_send_response(channel[0],56,&answer,readonly,1000) == -EINVAL);
    CHECK(sucrune_broker_send_response(channel[0],SUCRUNE_BROKER_OPEN_READ,&answer,-1,1000) == 0);
    CHECK(sucrune_broker_receive_response(channel[1],SUCRUNE_BROKER_OPEN_READ,&received,&right,1000) == 0);
    CHECK(received.result == 3 && right == -1);

    /* Force the kernel to discard the optional right on receipt (MSG_CTRUNC).
     * The complete slot reply and protocol alignment must survive. */
    CHECK(sucrune_broker_send_response(channel[0],SUCRUNE_BROKER_OPEN_READ,&answer,readonly,1000) == 0);
    struct rlimit old_limit, limited;
    CHECK(getrlimit(RLIMIT_NOFILE,&old_limit) == 0);
    limited = old_limit;
    limited.rlim_cur = 0;
    CHECK(setrlimit(RLIMIT_NOFILE,&limited) == 0);
    int rc = sucrune_broker_receive_response(channel[1],SUCRUNE_BROKER_OPEN_READ,&received,&right,1000);
    CHECK(setrlimit(RLIMIT_NOFILE,&old_limit) == 0);
    CHECK(rc == 0 && received.result == 3 && right == -1);
    CHECK(sucrune_broker_send_response(channel[0],SUCRUNE_BROKER_OPEN_READ,&answer,readonly,1000) == 0);
    CHECK(sucrune_broker_receive_response(channel[1],SUCRUNE_BROKER_OPEN_READ,&received,&right,1000) == 0);
    CHECK(received.result == 3 && right >= 0 && close(right) == 0);
    close_pair(channel);
    CHECK(close(readonly) == 0 && close(writable) == 0 && close(path_only) == 0 && close(dir) == 0);
    CHECK(count_fds() == before);
    passed++;
}

int main(void) {
    normal_files_and_rights(); request_rights_and_truncation(); malformed_responses_close_every_right(); bounded_wait_and_queued_cleanup();
    reject_swapped_socket_types();
    optional_read_replies();
    printf("Broker transport: %u/%u groups passed; real SCM_RIGHTS, rejected-right cleanup and bounded waits. No Android isolated-runner claim.\n", passed, passed);
    return 0;
}
