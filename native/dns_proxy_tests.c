#include "dns_proxy.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "%s:%d: %s (errno=%d)\n", __FILE__, __LINE__, #expr, errno); \
    exit(1); \
} } while (0)

#define PACKET_SPACE 2048U
#define ID 0x37b9U
static unsigned int passed;
static const unsigned char ipv4[] = {192, 0, 2, 37};
static const unsigned char ipv6[] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 37};

static void put16(unsigned char *p, unsigned int value) {
    p[0] = (unsigned char)(value >> 8);
    p[1] = (unsigned char)value;
}

static unsigned int get16(const unsigned char *p) {
    return ((unsigned int)p[0] << 8) | p[1];
}

/* marker.test. IN type, a single question with RD set. */
static size_t query(unsigned char *wire, unsigned int id, const char *marker, unsigned int type) {
    size_t size = strlen(marker);
    CHECK(size > 0U && size <= 63U);
    memset(wire, 0, 12U);
    put16(wire, id);
    wire[2] = 1U;
    wire[5] = 1U;
    wire[12] = (unsigned char)size;
    memcpy(wire + 13U, marker, size);
    size_t offset = 13U + size;
    memcpy(wire + offset, "\004test\000", 6U);
    offset += 6U;
    put16(wire + offset, type);
    put16(wire + offset + 2U, 1U);
    return offset + 4U;
}

static size_t add_opt(unsigned char *wire, size_t offset, unsigned int udp_size) {
    wire[11]++;
    static const unsigned char opt[] = {0, 0, 41, 0, 0, 0, 0, 0, 0, 0, 0};
    memcpy(wire + offset, opt, sizeof(opt));
    put16(wire + offset + 3U, udp_size);
    return offset + sizeof(opt);
}

/* Build a deterministic DNS packet independently of the proxy's codec.
 * Marker 'x' means NXDOMAIN, 'z' NODATA, and 'l' a 40-record answer. */
static size_t fixture_answer(const unsigned char *request, size_t query_size, unsigned char *wire) {
    CHECK(query_size >= 24U && query_size <= 100U);
    CHECK(request[11] == 0U);
    unsigned int type = get16(request + query_size - 4U);
    size_t data_size = type == 28U ? sizeof(ipv6) : sizeof(ipv4);
    CHECK(type == 1U || type == 28U);
    unsigned int marker = request[13];
    memcpy(wire, request, query_size);
    wire[2] = 0x81U;
    wire[3] = marker == 'x' ? 0x83U : 0x80U;
    unsigned int records = marker == 'x' || marker == 'z' ? 0U : marker == 'l' ? 40U : 1U;
    put16(wire + 6U, records);
    size_t offset = query_size;
    for (unsigned int i = 0U; i < records; i++) {
        static const unsigned char record[] = {0xc0, 12, 0, 0, 0, 1, 0, 0, 0, 37, 0, 0};
        CHECK(offset + sizeof(record) + data_size <= PACKET_SPACE);
        memcpy(wire + offset, record, sizeof(record));
        put16(wire + offset + 2U, type);
        put16(wire + offset + 10U, (unsigned int)data_size);
        offset += sizeof(record);
        memcpy(wire + offset, type == 28U ? ipv6 : ipv4, data_size);
        offset += data_size;
    }
    return offset;
}

static void codec_question_and_edns(void) {
    unsigned char wire[PACKET_SPACE];
    struct sucrune_dns_question result;
    size_t size = query(wire, ID, "MiXeD", 28U);
    CHECK(sucrune_dns_parse_query(wire, size, &result) == 0);
    static const unsigned char canonical[] = {5,'m','i','x','e','d',4,'t','e','s','t',0,0,28,0,1};
    CHECK(result.id == ID && result.key_length == sizeof(canonical));
    CHECK(memcmp(result.key, canonical, sizeof(canonical)) == 0);
    CHECK(result.wire_end == size && result.udp_limit == 512U);
    size_t full = add_opt(wire, size, 1232U);
    CHECK(sucrune_dns_parse_query(wire, full, &result) == 0 && result.udp_limit == 1232U);
    CHECK(result.wire_end == size);
    put16(wire + size + 3U, 0U);
    CHECK(sucrune_dns_parse_query(wire, full, &result) == 0 && result.udp_limit == 512U);
    put16(wire + size + 3U, 65535U);
    CHECK(sucrune_dns_parse_query(wire, full, &result) == 0 && result.udp_limit == 65507U);
    passed++;
}

static void codec_malformed_queries(void) {
    unsigned char wire[PACKET_SPACE];
    struct sucrune_dns_question result;
    size_t size = query(wire, ID, "query", 1U);
    wire[12] = 0xc0U;
    wire[13] = 12U;
    CHECK(sucrune_dns_parse_query(wire, size, &result) < 0); /* self loop */
    wire[13] = 0xffU;
    CHECK(sucrune_dns_parse_query(wire, size, &result) < 0); /* out of range */
    size = query(wire, ID, "query", 1U);
    wire[12] = 0x40U;
    CHECK(sucrune_dns_parse_query(wire, size, &result) < 0);
    size = query(wire, ID, "query", 1U);
    CHECK(sucrune_dns_parse_query(wire, size - 1U, &result) < 0);
    wire[size] = 0;
    CHECK(sucrune_dns_parse_query(wire, size + 1U, &result) < 0);
    size = add_opt(wire, size, 1232U);
    CHECK(sucrune_dns_parse_query(wire, size - 1U, &result) < 0);
    size = add_opt(wire, size, 1232U);
    CHECK(sucrune_dns_parse_query(wire, size, &result) < 0);
    passed++;
}

static void codec_answer_correlation(void) {
    unsigned char request[PACKET_SPACE], wire[PACKET_SPACE];
    struct sucrune_dns_question result;
    size_t qsize = query(request, ID, "Alpha", 1U);
    size_t size = fixture_answer(request, qsize, wire);
    CHECK(sucrune_dns_parse_query(request, qsize, &result) == 0);
    wire[13] = 'a';
    CHECK(sucrune_dns_validate_answer(wire, size, &result) == 0);
    memset(wire+size,0xa7,6U); /* Nonzero Android resolver trailer is not DNS data. */
    CHECK(sucrune_dns_system_answer_length(wire, size+6U, &result) == (int)size);
    CHECK(sucrune_dns_validate_answer(wire, size+6U, &result) < 0);
    CHECK(sucrune_dns_system_answer_length(wire, size-1U, &result) < 0);
    put16(wire+6U,2U); /* More counted records than the buffer contains. */
    CHECK(sucrune_dns_system_answer_length(wire, size+6U, &result) < 0);
    put16(wire+6U,1U);
    CHECK(sucrune_dns_validate_answer(wire, size - 1U, &result) < 0);
    wire[13] = 'b';
    CHECK(sucrune_dns_validate_answer(wire, size, &result) < 0);
    wire[13] = 'a';
    wire[0] ^= 1U;
    CHECK(sucrune_dns_validate_answer(wire, size, &result) < 0);
    wire[0] ^= 1U;
    wire[qsize - 3U] = 28U;
    CHECK(sucrune_dns_validate_answer(wire, size, &result) < 0);
    wire[qsize - 3U] = 1U;
    wire[qsize + 1U] = (unsigned char)qsize; /* answer's RR points to itself */
    CHECK(sucrune_dns_validate_answer(wire, size, &result) < 0);
    passed++;
}

#if !defined(SUCRUNE_DNS_CODEC_ONLY)
#include <arpa/inet.h>
#include <dirent.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define NETWORK_HANDLE UINT64_C(0xb86afe90deba13ac)
#define TOKEN UINT64_C(0xee35ab10)

struct fake {
    atomic_int submitted, collecting, consumed, cancelled, peer, release_submit;
};

static int64_t monotonic_ms(void) {
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static void wait_count(atomic_int *count, int minimum) {
    int64_t deadline = monotonic_ms() + 3000;
    while (atomic_load(count) < minimum) {
        CHECK(monotonic_ms() < deadline);
        const struct timespec tick = {0, 1000000};
        (void)nanosleep(&tick, NULL);
    }
}

static int read_all(int fd, unsigned char *buffer, size_t size) {
    while (size > 0U) {
        ssize_t got = recv(fd, buffer, size, 0);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) return -errno;
        if (got == 0) return -ECONNRESET;
        buffer += (size_t)got;
        size -= (size_t)got;
    }
    return 0;
}

static void write_all(int fd, const unsigned char *buffer, size_t size) {
    while (size > 0U) {
        ssize_t sent = send(fd, buffer, size, MSG_NOSIGNAL);
        if (sent < 0 && errno == EINTR) continue;
        CHECK(sent > 0);
        buffer += (size_t)sent;
        size -= (size_t)sent;
    }
}

static int fake_submit(void *userdata, uint64_t network, const unsigned char *request, size_t size) {
    struct fake *fake = userdata;
    CHECK(network == NETWORK_HANDLE && size >= 24U);
    unsigned int marker = request[13];
    atomic_fetch_add(&fake->submitted, 1);
    if (marker == 'b') wait_count(&fake->release_submit, 1);
    int pair[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
    if (marker == 'p' || marker == 's') {
        if (marker == 's') {
            unsigned char partial[] = {0, 100, 0xab};
            write_all(pair[1], partial, sizeof(partial));
        }
        int previous = atomic_exchange(&fake->peer, pair[1]);
        CHECK(previous == -1);
        return pair[0];
    }
    unsigned char answer[PACKET_SPACE + 2U];
    size_t count = fixture_answer(request, size, answer + 2U);
    put16(answer, (unsigned int)count);
    write_all(pair[1], answer, count + 2U);
    CHECK(close(pair[1]) == 0);
    return pair[0];
}

static int fake_collect(void *userdata, int fd, int *rcode, unsigned char *answer, size_t capacity) {
    struct fake *fake = userdata;
    atomic_fetch_add(&fake->collecting, 1);
    unsigned char header[2];
    int result = read_all(fd, header, sizeof(header));
    if (result == 0) {
        size_t size = get16(header);
        CHECK(size >= 12U && size <= capacity);
        result = read_all(fd, answer, size);
        if (result == 0) {
            *rcode = (int)(answer[3] & 15U);
            result = (int)size;
        }
    }
    CHECK(close(fd) == 0);
    atomic_fetch_add(&fake->consumed, 1);
    return result;
}

static void fake_cancel(void *userdata, int fd) {
    struct fake *fake = userdata;
    CHECK(close(fd) == 0);
    atomic_fetch_add(&fake->cancelled, 1);
    atomic_fetch_add(&fake->consumed, 1);
}

struct fixture {
    struct fake fake;
    struct sucrune_dns_proxy *proxy;
    struct sockaddr_in endpoint;
    int fd_baseline;
};

static int fd_count(void) {
    DIR *directory = opendir("/proc/self/fd");
    CHECK(directory != NULL);
    int count = 0;
    struct dirent *item;
    while ((item = readdir(directory)) != NULL)
        if (item->d_name[0] != '.') count++;
    CHECK(closedir(directory) == 0);
    return count;
}

static void fixture_start(struct fixture *fixture, unsigned int timeout_ms) {
    fixture->fd_baseline = fd_count();
    atomic_init(&fixture->fake.submitted, 0);
    atomic_init(&fixture->fake.collecting, 0);
    atomic_init(&fixture->fake.consumed, 0);
    atomic_init(&fixture->fake.cancelled, 0);
    atomic_init(&fixture->fake.peer, -1);
    atomic_init(&fixture->fake.release_submit, 0);
    struct sucrune_dns_backend backend = {&fixture->fake, fake_submit, fake_collect, fake_cancel};
    struct sucrune_dns_config config = {NETWORK_HANDLE, timeout_ms};
    CHECK(sucrune_dns_proxy_start(&config, &backend, &fixture->proxy) == 0);
    uint16_t port = 0;
    CHECK(sucrune_dns_proxy_endpoint(fixture->proxy, &port) == 0 && port != 0U);
    fixture->endpoint = (struct sockaddr_in){.sin_family = AF_INET, .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
}

static int client(struct fixture *fixture, int transport, uint64_t token) {
    int type = transport == SUCRUNE_DNS_TCP ? SOCK_STREAM : SOCK_DGRAM;
    int fd = socket(AF_INET, type | SOCK_CLOEXEC, 0);
    CHECK(fd >= 0);
    struct timeval timeout = {3, 0};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(fd, (struct sockaddr *)&local, sizeof(local)) == 0);
    if (token != 0U)
        CHECK(sucrune_dns_proxy_allow_client(fixture->proxy, transport, fd, token) == 0);
    CHECK(connect(fd, (struct sockaddr *)&fixture->endpoint, sizeof(fixture->endpoint)) == 0);
    return fd;
}

static struct sucrune_dns_stats finish(struct fixture *fixture) {
    struct sucrune_dns_stats stats;
    sucrune_dns_proxy_request_stop(fixture->proxy);
    CHECK(sucrune_dns_proxy_join(fixture->proxy, 3000, &stats) == 0);
    CHECK(stats.joined && stats.listeners_closed && stats.pending == 0U);
    CHECK(stats.workers_started == SUCRUNE_DNS_WORKER_LIMIT && stats.workers_exited == stats.workers_started);
    CHECK(atomic_load(&fixture->fake.submitted) == atomic_load(&fixture->fake.consumed));
    CHECK(sucrune_dns_proxy_destroy(fixture->proxy) == 0);
    int peer = atomic_exchange(&fixture->fake.peer, -1);
    if (peer >= 0) CHECK(close(peer) == 0);
    CHECK(fd_count() == fixture->fd_baseline);
    return stats;
}

static void send_query(int fd, unsigned int id, const char *marker, unsigned int type) {
    unsigned char request[PACKET_SPACE];
    size_t size = query(request, id, marker, type);
    CHECK(send(fd, request, size, MSG_NOSIGNAL) == (ssize_t)size);
}

static void check_reply(const unsigned char *wire, size_t size, unsigned int id,
    const char *marker, unsigned int type) {
    unsigned char request[PACKET_SPACE], expected[PACKET_SPACE];
    size_t qsize = query(request, id, marker, type);
    size_t length = fixture_answer(request, qsize, expected);
    CHECK(size == length && memcmp(wire, expected, length) == 0);
}

static void expect_quiet(int fd) {
    struct pollfd wait = {fd, POLLIN, 0};
    int result;
    do { result = poll(&wait, 1U, 100); } while (result < 0 && errno == EINTR);
    CHECK(result == 0);
}

static void udp_permissions_and_answers(void) {
    struct fixture fixture;
    fixture_start(&fixture, 2000U);
    int denied = client(&fixture, SUCRUNE_DNS_UDP, 0);
    int left = client(&fixture, SUCRUNE_DNS_UDP, TOKEN);
    int right = client(&fixture, SUCRUNE_DNS_UDP, TOKEN + 1U);
    CHECK(sucrune_dns_proxy_allow_client(fixture.proxy, SUCRUNE_DNS_TCP, left, TOKEN + 2U) == -EPROTOTYPE);
    CHECK(sucrune_dns_proxy_allow_client(fixture.proxy, SUCRUNE_DNS_UDP, left, TOKEN + 2U) == -EEXIST);
    send_query(denied, ID, "denied", 1U);
    send_query(left, ID, "address", 1U);
    send_query(right, ID, "v6", 28U);
    unsigned char response[PACKET_SPACE];
    ssize_t got = recv(left, response, sizeof(response), 0);
    CHECK(got > 0);
    check_reply(response, (size_t)got, ID, "address", 1U);
    got = recv(right, response, sizeof(response), 0);
    CHECK(got > 0);
    check_reply(response, (size_t)got, ID, "v6", 28U);
    const char *errors[] = {"xnxdomain", "znodata"};
    for (size_t i = 0U; i < sizeof(errors) / sizeof(errors[0]); i++) {
        send_query(left, ID, errors[i], 1U);
        got = recv(left, response, sizeof(response), 0);
        CHECK(got > 0);
        check_reply(response, (size_t)got, ID, errors[i], 1U);
        CHECK((response[3] & 15U) == (i == 0U ? 3U : 0U) && get16(response + 6U) == 0U);
    }
    expect_quiet(denied);
    CHECK(close(denied) == 0 && close(left) == 0 && close(right) == 0);
    struct sucrune_dns_stats stats = finish(&fixture);
    CHECK(stats.unregistered >= 1U && stats.admitted == 4U && stats.answered == 4U);
    passed++;
}

static size_t frame(unsigned char *buffer, unsigned int id, const char *marker, unsigned int type) {
    size_t size = query(buffer + 2U, id, marker, type);
    put16(buffer, (unsigned int)size);
    return size + 2U;
}

static void check_frame(int tcp, unsigned int id, const char *marker, unsigned int type) {
    unsigned char prefix[2], answer[PACKET_SPACE];
    CHECK(read_all(tcp, prefix, sizeof(prefix)) == 0);
    size_t length = get16(prefix);
    CHECK(length > 0U && length <= sizeof(answer));
    CHECK(read_all(tcp, answer, length) == 0);
    check_reply(answer, length, id, marker, type);
}

static void udp_tc_then_tcp_pipeline(void) {
    struct fixture fixture;
    fixture_start(&fixture, 2000U);
    int udp = client(&fixture, SUCRUNE_DNS_UDP, TOKEN);
    send_query(udp, ID, "large", 1U);
    unsigned char answer[PACKET_SPACE], request[PACKET_SPACE];
    ssize_t got = recv(udp, answer, sizeof(answer), 0);
    size_t qsize = query(request, ID, "large", 1U);
    CHECK(got == (ssize_t)qsize && (answer[2] & 0x82U) == 0x82U);
    CHECK(get16(answer) == ID && get16(answer + 6U) == 0U);
    CHECK(memcmp(answer + 12U, request + 12U, qsize - 12U) == 0);
    int tcp = client(&fixture, SUCRUNE_DNS_TCP, TOKEN + 1U);
    unsigned char pipeline[PACKET_SPACE];
    size_t total = frame(pipeline, ID, "large", 1U);
    total += frame(pipeline + total, ID + 1U, "v6", 28U);
    write_all(tcp, pipeline, 1U);         /* incomplete length prefix */
    expect_quiet(tcp);
    write_all(tcp, pipeline + 1U, 7U);   /* incomplete question */
    expect_quiet(tcp);
    write_all(tcp, pipeline + 8U, total - 8U);
    check_frame(tcp, ID, "large", 1U);
    check_frame(tcp, ID + 1U, "v6", 28U);
    CHECK(close(udp) == 0 && close(tcp) == 0);
    struct sucrune_dns_stats stats = finish(&fixture);
    CHECK(stats.answered == 3U && stats.backend_errors == 0U);
    passed++;
}

static void pending_timeout(void) {
    struct fixture fixture;
    fixture_start(&fixture, 300U);
    int fd = client(&fixture, SUCRUNE_DNS_UDP, TOKEN);
    send_query(fd, ID, "pending", 28U);
    unsigned char answer[PACKET_SPACE], request[PACKET_SPACE];
    ssize_t got = recv(fd, answer, sizeof(answer), 0);
    size_t size = query(request, ID, "pending", 28U);
    CHECK(got == (ssize_t)size && get16(answer) == ID && (answer[3] & 15U) == 2U);
    CHECK(memcmp(answer + 12U, request + 12U, size - 12U) == 0);
    CHECK(close(fd) == 0);
    struct sucrune_dns_stats stats = finish(&fixture);
    CHECK(stats.timed_out == 1U && stats.answered == 1U);
    CHECK(atomic_load(&fixture.fake.cancelled) == 1 && atomic_load(&fixture.fake.collecting) == 0);
    passed++;
}

static void partial_collect_stop(void) {
    struct fixture fixture;
    fixture_start(&fixture, 10000U);
    int fd = client(&fixture, SUCRUNE_DNS_UDP, TOKEN);
    send_query(fd, ID, "split", 1U);
    wait_count(&fixture.fake.collecting, 1);
    sucrune_dns_proxy_request_stop(fixture.proxy);
    CHECK(close(fd) == 0);
    struct sucrune_dns_stats stats = finish(&fixture);
    CHECK(stats.cancelled == 1U && stats.timed_out == 0U && stats.answered == 0U);
    CHECK(atomic_load(&fixture.fake.cancelled) == 0 && atomic_load(&fixture.fake.consumed) == 1);
    passed++;
}

static void blocked_submit_retry_join(void) {
    struct fixture fixture;
    fixture_start(&fixture, 5000U);
    int fd = client(&fixture, SUCRUNE_DNS_UDP, TOKEN);
    send_query(fd, ID, "block", 1U);
    wait_count(&fixture.fake.submitted, 1);
    sucrune_dns_proxy_request_stop(fixture.proxy);
    struct sucrune_dns_stats snapshot;
    CHECK(sucrune_dns_proxy_join(fixture.proxy, 30, &snapshot) == -ETIMEDOUT);
    CHECK(snapshot.joined == 0 && snapshot.pending == 1U && snapshot.workers_exited < snapshot.workers_started);
    CHECK(sucrune_dns_proxy_destroy(fixture.proxy) == -EBUSY);
    atomic_store(&fixture.fake.release_submit, 1);
    CHECK(close(fd) == 0);
    struct sucrune_dns_stats stats = finish(&fixture);
    CHECK(stats.cancelled == 1U && atomic_load(&fixture.fake.cancelled) == 1);
    passed++;
}

static void revoked_query_does_not_reach_replacement(void) {
    struct fixture fixture;
    fixture_start(&fixture, 4000U);
    int fd = client(&fixture, SUCRUNE_DNS_UDP, TOKEN);
    send_query(fd, ID, "split", 1U);
    wait_count(&fixture.fake.collecting, 1);
    CHECK(sucrune_dns_proxy_remove_client(fixture.proxy, TOKEN) == 0);
    CHECK(sucrune_dns_proxy_remove_client(fixture.proxy, TOKEN) == -ENOENT);
    CHECK(sucrune_dns_proxy_allow_client(fixture.proxy, SUCRUNE_DNS_UDP, fd, TOKEN + 1U) == 0);
    send_query(fd, ID, "replacement", 1U);
    unsigned char answer[PACKET_SPACE];
    ssize_t got = recv(fd, answer, sizeof(answer), 0);
    CHECK(got > 0);
    check_reply(answer, (size_t)got, ID, "replacement", 1U);
    expect_quiet(fd);
    CHECK(close(fd) == 0);
    struct sucrune_dns_stats stats = finish(&fixture);
    CHECK(stats.cancelled == 1U && stats.answered == 1U && stats.admitted == 2U);
    passed++;
}
#endif

int main(void) {
    codec_question_and_edns();
    codec_malformed_queries();
    codec_answer_correlation();
#if !defined(SUCRUNE_DNS_CODEC_ONLY)
    udp_permissions_and_answers();
    udp_tc_then_tcp_pipeline();
    pending_timeout();
    partial_collect_stop();
    blocked_submit_retry_join();
    revoked_query_does_not_reach_replacement();
    const char *scope = "fake-resolver-loopback";
#else
    const char *scope = "codec-only";
#endif
    printf("{\"suite\":\"dns-proxy\",\"scope\":\"%s\",\"passed\":%u,\"skipped\":0}\n", scope, passed);
    return 0;
}
