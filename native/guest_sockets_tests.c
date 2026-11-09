#include "guest_sockets.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(value) do { if (!(value)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #value); exit(1); } } while (0)
static unsigned int passed, skipped;
static void ipv4_wire(void) {
    const unsigned char input[16] = {2, 0, 0x1f, 0x90, 127, 0, 0, 1};
    struct sucrune_socket_address address;
    CHECK(sucrune_socket_address_decode(input, sizeof(input), &address) == 0);
    CHECK(address.family == 2U && address.port == 8080U && address.address[0] == 127U && address.address[3] == 1U);
    CHECK(address.scope_id == 0U && address.flowinfo == 0U && address.unix_length == 0U);
    unsigned char output[20]; memset(output, 0xa7, sizeof(output)); size_t size = 999U;
    CHECK(sucrune_socket_address_encode(&address, output, sizeof(output), &size) == 0);
    CHECK(size == sizeof(input) && memcmp(input, output, sizeof(input)) == 0 && output[16] == 0xa7U);
    memset(output, 0xa7, sizeof(output));
    CHECK(sucrune_socket_address_encode(&address, output, 3U, &size) == 0);
    CHECK(size == 16U && memcmp(input, output, 3U) == 0 && output[3] == 0xa7U);
    CHECK(sucrune_socket_address_encode(&address, NULL, 0U, &size) == 0 && size == 16U);
    passed++;
}
static void ipv6_wire(void) {
    const unsigned char input[28] = {10, 0, 0x01, 0xbb, 0x12, 0x34, 0x56, 0x78,
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x44, 0x33, 0x22, 0x11};
    struct sucrune_socket_address address;
    CHECK(sucrune_socket_address_decode(input, sizeof(input), &address) == 0);
    CHECK(address.family == 10U && address.port == 443U && address.flowinfo == UINT32_C(0x12345678));
    CHECK(address.scope_id == UINT32_C(0x11223344) && address.address[0] == 0xfeU && address.address[15] == 1U);
    unsigned char output[28]; size_t size;
    CHECK(sucrune_socket_address_encode(&address, output, sizeof(output), &size) == 0);
    CHECK(size == sizeof(input) && memcmp(input, output, sizeof(input)) == 0);
    passed++;
}
static void unix_counted_names(void) {
    const unsigned char input[] = {1, 0, 0, 's', 'u', 0, 'g', 0xff};
    struct sucrune_socket_address address;
    CHECK(sucrune_socket_address_decode(input, sizeof(input), &address) == 0);
    CHECK(address.family == 1U && address.unix_length == sizeof(input) - 2U);
    unsigned char output[110]; size_t size;
    CHECK(sucrune_socket_address_encode(&address, output, sizeof(output), &size) == 0);
    CHECK(size == sizeof(input) && memcmp(input, output, size) == 0);
    unsigned char full[110]; memset(full, 'x', sizeof(full)); full[0] = 1; full[1] = 0;
    CHECK(sucrune_socket_address_decode(full, sizeof(full), &address) == 0 && address.unix_length == 108U);
    CHECK(sucrune_socket_address_encode(&address, output, sizeof(output), &size) == 0);
    CHECK(size == 110U && memcmp(full, output, size) == 0);
    const unsigned char unnamed[2] = {1, 0};
    CHECK(sucrune_socket_address_decode(unnamed, sizeof(unnamed), &address) == 0 && address.unix_length == 0U);
    const unsigned char unspec[2] = {0, 0};
    CHECK(sucrune_socket_address_decode(unspec, sizeof(unspec), &address) == 0);
    CHECK(sucrune_socket_address_encode(&address, output, sizeof(output), &size) == 0 && size == 2U && output[0] == 0U);
    passed++;
}
static void codec_errors_are_atomic(void) {
    unsigned char input[129] = {2, 0};
    struct sucrune_socket_address address, before; memset(&address, 0x54, sizeof(address)); before = address;
    CHECK(sucrune_socket_address_decode(input, 1U, &address) == -EINVAL);
    CHECK(sucrune_socket_address_decode(input, 15U, &address) == -EINVAL);
    CHECK(sucrune_socket_address_decode(input, sizeof(input), &address) == -EINVAL);
    input[0] = 10; CHECK(sucrune_socket_address_decode(input, 27U, &address) == -EINVAL);
    input[0] = 1; CHECK(sucrune_socket_address_decode(input, 111U, &address) == -EINVAL);
    input[0] = 99; CHECK(sucrune_socket_address_decode(input, 16U, &address) == -EAFNOSUPPORT);
    CHECK(sucrune_socket_address_decode(NULL, 16U, &address) == -EFAULT);
    CHECK(memcmp(&address, &before, sizeof(address)) == 0);
    unsigned char output[128]; memset(output, 0x37, sizeof(output)); size_t size = 67U;
    address.family = 99U;
    CHECK(sucrune_socket_address_encode(&address, output, sizeof(output), &size) == -EAFNOSUPPORT);
    CHECK(size == 67U && output[0] == 0x37U);
    address.family = 1U; address.unix_length = 109U;
    CHECK(sucrune_socket_address_encode(&address, output, sizeof(output), &size) == -EINVAL);
    CHECK(size == 67U && output[0] == 0x37U);
    passed++;
}

#if !defined(SUCRUNE_SOCKET_CODEC_ONLY)
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
struct fixture {
    int handles[4], failed[2], commit_error, reserve_error, acquired, released, cancel_count, reuse_on_pin, pin_error;
    unsigned int flags[4];
    size_t count, reserved;
    struct sucrune_local_io io;
};
static int reserve(void *opaque, size_t count, uintptr_t *token) {
    struct fixture *f = opaque;
    if (f->reserve_error != 0) return f->reserve_error;
    if (f->reserved != 0U || count > 4U - f->count) return -EMFILE;
    f->reserved = count; *token = count; return 0;
}
static int commit(void *opaque, uintptr_t token, size_t count,
                  const struct sucrune_local_new_fd *fds, int32_t *output) {
    struct fixture *f = opaque;
    CHECK(token == count && count == 2U && f->reserved == count);
    if (f->commit_error != 0) {
        f->failed[0] = fds[0].host_fd; f->failed[1] = fds[1].host_fd; return f->commit_error;
    }
    for (size_t i = 0U; i < count; i++) {
        output[i] = (int32_t)f->count;
        f->handles[f->count] = fds[i].host_fd; f->flags[f->count++] = fds[i].descriptor_flags;
        CHECK((fds[i].status_flags & O_ACCMODE) == O_RDWR);
    }
    f->reserved = 0U; return 0;
}
static void cancel(void *opaque, uintptr_t token) {
    struct fixture *f = opaque; CHECK(token == f->reserved); f->reserved = 0U; f->cancel_count++;
}
static int acquire(void *opaque, const int32_t *guest, size_t count,
                   enum sucrune_local_pin_mode mode, struct sucrune_local_pin *pins) {
    struct fixture *f = opaque; CHECK(count == 1U && mode == SUCRUNE_LOCAL_RETAINED_WAIT); f->acquired++;
    pins[0] = (struct sucrune_local_pin){.host_fd = -1};
    if (f->pin_error != 0) { pins[0].error = f->pin_error; return 0; }
    if (guest[0] < 0 || guest[0] >= (int32_t)f->count) { pins[0].error = -EBADF; return 0; }
    int original = f->handles[guest[0]];
    pins[0].host_fd = fcntl(original, F_DUPFD_CLOEXEC, 3);
    CHECK(pins[0].host_fd >= 0);
    if (f->reuse_on_pin != 0) {
        f->reuse_on_pin = 0; CHECK(close(original) == 0);
        f->handles[guest[0]] = open("/dev/null", O_RDONLY | O_CLOEXEC);
        CHECK(f->handles[guest[0]] == original);
    }
    return 0;
}
static void release(void *opaque, enum sucrune_local_pin_mode mode, struct sucrune_local_pin *pins, size_t count) {
    struct fixture *f = opaque; CHECK(count == 1U && mode == SUCRUNE_LOCAL_RETAINED_WAIT); f->released++;
    if (pins[0].host_fd >= 0) CHECK(close(pins[0].host_fd) == 0);
}
static void initialize(struct fixture *f) {
    memset(f, 0, sizeof(*f));
    f->io = (struct sucrune_local_io){.context = f, .ops = {.reserve = reserve, .commit = commit,
        .cancel = cancel, .acquire_many = acquire, .release_many = release}};
}
static void finish(struct fixture *f) {
    CHECK(f->reserved == 0U && f->acquired == f->released);
    for (size_t i = 0U; i < f->count; i++) CHECK(close(f->handles[i]) == 0);
    passed++;
}
static void pair_flags_and_transport(void) {
    struct fixture f; initialize(&f); int32_t pair[2] = {-7, -8};
    CHECK(sucrune_socket_pair(&f.io, AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair) == 0);
    CHECK(pair[0] == 0 && pair[1] == 1 && f.flags[0] == 0U && f.flags[1] == 0U);
    CHECK((fcntl(f.handles[0], F_GETFD) & FD_CLOEXEC) != 0 && (fcntl(f.handles[1], F_GETFD) & FD_CLOEXEC) != 0);
    CHECK((fcntl(f.handles[0], F_GETFL) & O_NONBLOCK) != 0);
    char buffer[8]; CHECK(recv(f.handles[1], buffer, sizeof(buffer), 0) == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));
    CHECK(send(f.handles[0], "ping", 4U, MSG_NOSIGNAL) == 4);
    CHECK(recv(f.handles[1], buffer, sizeof(buffer), 0) == 4 && memcmp(buffer, "ping", 4U) == 0);
    CHECK(shutdown(f.handles[0], SHUT_WR) == 0 && recv(f.handles[1], buffer, sizeof(buffer), 0) == 0);
    int alias = fcntl(f.handles[0], F_DUPFD_CLOEXEC, 3); CHECK(alias >= 0);
    CHECK(fcntl(alias, F_SETFL, fcntl(alias, F_GETFL) & ~O_NONBLOCK) == 0);
    CHECK((fcntl(f.handles[0], F_GETFL) & O_NONBLOCK) == 0 && (fcntl(f.handles[1], F_GETFL) & O_NONBLOCK) != 0);
    CHECK(close(alias) == 0); finish(&f);
}
static void creation_rollback(void) {
    struct fixture f; initialize(&f); int32_t pair[2] = {-7, -8};
    CHECK(sucrune_socket_pair(&f.io, AF_INET, SOCK_STREAM, 0, pair) == -EAFNOSUPPORT);
    CHECK(sucrune_socket_pair(&f.io, AF_UNIX, SOCK_RAW, 0, pair) == -EINVAL);
    CHECK(sucrune_socket_pair(&f.io, AF_UNIX, SOCK_STREAM, 1, pair) == -EPROTONOSUPPORT);
    f.reserve_error = -EMFILE;
    CHECK(sucrune_socket_pair(&f.io, AF_UNIX, SOCK_STREAM, 0, pair) == -EMFILE && f.cancel_count == 0);
    f.reserve_error = 0; f.commit_error = -EFAULT;
    CHECK(sucrune_socket_pair(&f.io, AF_UNIX, SOCK_STREAM, 0, pair) == -EFAULT);
    CHECK(f.count == 0U && f.reserved == 0U && f.cancel_count == 1 && pair[0] == -7 && pair[1] == -8);
    CHECK(fcntl(f.failed[0], F_GETFD) == -1 && errno == EBADF);
    CHECK(fcntl(f.failed[1], F_GETFD) == -1 && errno == EBADF);
    f.commit_error = 0;
    CHECK(sucrune_socket_pair(&f.io, AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, pair) == 0);
    CHECK(f.flags[0] == SUCRUNE_LOCAL_CLOEXEC && f.flags[1] == SUCRUNE_LOCAL_CLOEXEC);
    finish(&f);
}
static void options_and_retained_identity(void) {
    struct fixture f; initialize(&f); int32_t pair[2];
    CHECK(sucrune_socket_pair(&f.io, AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    unsigned char output[8]; memset(output, 0xa6, sizeof(output)); size_t length = 77U;
    CHECK(sucrune_socket_get_option(&f.io, pair[0], SOL_SOCKET, SO_TYPE, output, sizeof(output), &length) == 0);
    CHECK(length == 4U && output[0] == SOCK_STREAM && output[1] == 0U && output[2] == 0U && output[3] == 0U && output[4] == 0xa6U);
    CHECK(sucrune_socket_get_option(&f.io, pair[0], SOL_SOCKET, SO_TYPE, output, 1U, &length) == 0 && length == 1U);
    CHECK(sucrune_socket_get_option(&f.io, pair[0], SOL_SOCKET, SO_ERROR, NULL, 0U, &length) == 0 && length == 0U);
    int acquired = f.acquired; length = 77U;
    CHECK(sucrune_socket_get_option(&f.io, pair[0], SOL_SOCKET, SO_PEERCRED, output, sizeof(output), &length) == -ENOPROTOOPT);
    CHECK(length == 77U && f.acquired == acquired);
    CHECK(sucrune_socket_get_option(&f.io, -1, SOL_SOCKET, SO_TYPE, output, sizeof(output), &length) == -EBADF && length == 77U);
    f.reuse_on_pin = 1;
    CHECK(sucrune_socket_get_option(&f.io, pair[0], SOL_SOCKET, SO_TYPE, output, sizeof(output), &length) == 0);
    CHECK(length == 4U && output[0] == SOCK_STREAM);
    memset(output, 0xa6, sizeof(output)); length = 77U;
    CHECK(sucrune_socket_get_option(&f.io, pair[0], SOL_SOCKET, SO_TYPE, output, sizeof(output), &length) == -ENOTSOCK);
    CHECK(length == 77U && output[0] == 0xa6U); finish(&f);
}

static void missing_local_alias_is_not_a_socket(void) {
    struct fixture f; initialize(&f); int32_t pair[2];
    CHECK(sucrune_socket_pair(&f.io, AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    /* Models the FD table changing from local to broker before acquisition:
     * the callback acquired successfully, but no local FD may be returned. */
    f.pin_error = -ENOTSUP;
    unsigned char output[16]; memset(output, 0xa6, sizeof(output)); size_t length = 77U;
    CHECK(sucrune_socket_get_option(&f.io, pair[0], SOL_SOCKET, SO_TYPE, output, sizeof(output), &length) == -ENOTSOCK);
    for (int peer = 0; peer <= 1; peer++)
        CHECK(sucrune_socket_get_name(&f.io, pair[0], peer, output, sizeof(output), &length) == -ENOTSOCK);
    CHECK(length == 77U && f.acquired == 3 && f.released == 3);
    for (size_t i = 0U; i < sizeof(output); i++) CHECK(output[i] == 0xa6U);
    f.pin_error = -EIO;
    CHECK(sucrune_socket_get_option(&f.io, pair[0], SOL_SOCKET, SO_TYPE, output, sizeof(output), &length) == -EIO);
    CHECK(sucrune_socket_get_name(&f.io, pair[0], 0, output, sizeof(output), &length) == -EIO);
    CHECK(length == 77U && f.acquired == 5 && f.released == 5);
    for (size_t i = 0U; i < sizeof(output); i++) CHECK(output[i] == 0xa6U);
    finish(&f);
}

static void unnamed_names_and_retained_identity(void) {
    struct fixture f; initialize(&f); int32_t pair[2];
    CHECK(sucrune_socket_pair(&f.io, AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    struct sockaddr_un native; socklen_t native_length = sizeof(native);
    CHECK(getsockname(f.handles[0], (struct sockaddr *)&native, &native_length) == 0);
    CHECK(native_length == offsetof(struct sockaddr_un, sun_path) && native.sun_family == AF_UNIX);
    unsigned char output[16]; size_t length = 77U;
    for (int peer = 0; peer <= 1; peer++) {
        memset(output, 0xa6, sizeof(output));
        CHECK(sucrune_socket_get_name(&f.io, pair[0], peer, output, sizeof(output), &length) == 0);
        CHECK(length == 2U && output[0] == 1U && output[1] == 0U && output[2] == 0xa6U);
        memset(output, 0xa6, sizeof(output));
        CHECK(sucrune_socket_get_name(&f.io, pair[0], peer, output, 1U, &length) == 0);
        CHECK(length == 2U && output[0] == 1U && output[1] == 0xa6U);
        CHECK(sucrune_socket_get_name(&f.io, pair[0], peer, NULL, 0U, &length) == 0 && length == 2U);
    }
    int acquired = f.acquired; length = 77U; memset(output, 0xa6, sizeof(output));
    CHECK(sucrune_socket_get_name(&f.io, pair[0], -1, output, sizeof(output), &length) == -EINVAL);
    CHECK(sucrune_socket_get_name(&f.io, pair[0], 2, output, sizeof(output), &length) == -EINVAL);
    CHECK(sucrune_socket_get_name(&f.io, pair[0], 0, NULL, 1U, &length) == -EFAULT);
    CHECK(sucrune_socket_get_name(&f.io, pair[0], 0, output, sizeof(output), NULL) == -EFAULT);
    CHECK(f.acquired == acquired && length == 77U && output[0] == 0xa6U);
    CHECK(sucrune_socket_get_name(&f.io, -1, 0, output, sizeof(output), &length) == -EBADF);
    CHECK(length == 77U && output[0] == 0xa6U);
    f.reuse_on_pin = 1;
    CHECK(sucrune_socket_get_name(&f.io, pair[0], 1, output, sizeof(output), &length) == 0);
    CHECK(length == 2U && output[0] == 1U && output[1] == 0U);
    memset(output, 0xa6, sizeof(output)); length = 77U;
    CHECK(sucrune_socket_get_name(&f.io, pair[0], 0, output, sizeof(output), &length) == -ENOTSOCK);
    CHECK(length == 77U && output[0] == 0xa6U);
    finish(&f);
}

static void named_unix_addresses_are_private(void) {
    struct fixture f; initialize(&f);
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
    f.handles[0] = fd; f.count = 1U;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    int chars = snprintf(address.sun_path + 1U, sizeof(address.sun_path) - 1U,
                         "sucrune-name-query-%ld", (long)getpid());
    CHECK(chars > 0 && (size_t)chars < sizeof(address.sun_path) - 1U);
    socklen_t size = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1U + (size_t)chars);
    if (bind(fd, (const struct sockaddr *)&address, size) != 0) {
        int error = errno;
        CHECK(error == EACCES || error == EPERM);
        CHECK(close(fd) == 0);
        skipped++;
        printf("SKIP named_unix_addresses_are_private: abstract bind denied with errno=%d.\n", error);
        return;
    }
    unsigned char output[128]; memset(output, 0xa6, sizeof(output)); size_t length = 77U;
    CHECK(sucrune_socket_get_name(&f.io, 0, 0, output, sizeof(output), &length) == -ENOTSUP);
    CHECK(length == 77U && output[0] == 0xa6U && output[127] == 0xa6U);
    CHECK(sucrune_socket_get_name(&f.io, 0, 0, NULL, 0U, &length) == -ENOTSUP && length == 77U);
    CHECK(sucrune_socket_get_name(&f.io, 0, 1, output, sizeof(output), &length) == -ENOTCONN);
    CHECK(length == 77U && output[0] == 0xa6U);
    finish(&f); /* Abstract UNIX names disappear with the last descriptor. */
}

static void inet_name_length_and_truncation(void) {
    struct fixture f; initialize(&f);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
    f.handles[0] = fd; f.count = 1U;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = 0};
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(fd, (const struct sockaddr *)&address, sizeof(address)) == 0);
    socklen_t native_length = sizeof(address);
    CHECK(getsockname(fd, (struct sockaddr *)&address, &native_length) == 0);
    CHECK(native_length == sizeof(address) && address.sin_port != 0);
    unsigned char output[20]; memset(output, 0xa6, sizeof(output)); size_t length = 77U;
    CHECK(sucrune_socket_get_name(&f.io, 0, 0, output, sizeof(output), &length) == 0);
    CHECK(length == 16U && output[0] == 2U && output[1] == 0U && output[4] == 127U &&
          output[5] == 0U && output[6] == 0U && output[7] == 1U && output[16] == 0xa6U);
    CHECK(memcmp(output + 2U, &address.sin_port, sizeof(address.sin_port)) == 0);
    for (size_t i = 8U; i < 16U; i++) CHECK(output[i] == 0U);
    memset(output, 0xa6, sizeof(output));
    CHECK(sucrune_socket_get_name(&f.io, 0, 0, output, 3U, &length) == 0 && length == 16U);
    CHECK(output[0] == 2U && output[1] == 0U && output[3] == 0xa6U);
    CHECK(sucrune_socket_get_name(&f.io, 0, 0, NULL, 0U, &length) == 0 && length == 16U);
    length = 77U; memset(output, 0xa6, sizeof(output));
    CHECK(sucrune_socket_get_name(&f.io, 0, 1, output, sizeof(output), &length) == -ENOTCONN);
    CHECK(length == 77U && output[0] == 0xa6U);
    finish(&f);
}
#endif

int main(void) {
    ipv4_wire(); ipv6_wire(); unix_counted_names(); codec_errors_are_atomic();
#if !defined(SUCRUNE_SOCKET_CODEC_ONLY)
    pair_flags_and_transport(); creation_rollback(); options_and_retained_identity();
    missing_local_alias_is_not_a_socket();
    unnamed_names_and_retained_identity(); named_unix_addresses_are_private(); inet_name_length_and_truncation();
#endif
    printf("Guest socket foundations: %u/%u passed, %u skipped; sockaddr codecs", passed, passed + skipped, skipped);
#if !defined(SUCRUNE_SOCKET_CODEC_ONLY)
    printf(", local socketpair rollback/transport, retained query identity and private socket names");
#endif
    puts(". No Android app network capability is established.");
    return 0;
}
