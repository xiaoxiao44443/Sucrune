#include "network_probe.h"
#include <string.h>

int sucrune_network_probe_loopback_bytes(const unsigned char *address, size_t length) {
    static const unsigned char v4[4] = {127, 0, 0, 1};
    static const unsigned char v6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    static const unsigned char mapped[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1};
    if (address == NULL) return 0;
    if (length == sizeof(v4)) return memcmp(address, v4, sizeof(v4)) == 0;
    if (length == sizeof(v6))
        return memcmp(address, v6, sizeof(v6)) == 0 || memcmp(address, mapped, sizeof(mapped)) == 0;
    return 0;
}

#ifndef SUCRUNE_NETWORK_PROBE_CODEC_ONLY

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define PROBE_OPERATIONS 40U

struct operation {
    const char *name;
    int64_t rc;
    int error;
    int value;
    bool attempted;
    bool has_value;
};

struct probe {
    struct operation operations[PROBE_OPERATIONS];
    size_t count;
    int64_t started_ns, deadline_ns;
    unsigned owned_opened, owned_closed;
    bool close_failed, operation_overflow;
    size_t sent, received;
    bool echo_match;
};

struct writer { char *text; size_t capacity, used; bool failed; };

static int64_t monotonic_ns(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (int64_t)now.tv_sec * INT64_C(1000000000) + now.tv_nsec;
}

static int remaining_ms(const struct probe *p) {
    int64_t now = monotonic_ns();
    if (now < 0 || now >= p->deadline_ns) return 0;
    int64_t milliseconds = (p->deadline_ns - now + INT64_C(999999)) / INT64_C(1000000);
    return milliseconds > INT_MAX ? INT_MAX : (int)milliseconds;
}

static void note(struct probe *p, const char *name, int64_t rc, int error) {
    if (p->count >= PROBE_OPERATIONS) { p->operation_overflow = true; return; }
    p->operations[p->count++] = (struct operation){
        .name = name, .rc = rc, .error = error, .attempted = true
    };
}

static void note_value(struct probe *p, const char *name, int rc, int error, int value) {
    note(p, name, rc, error);
    if (!p->operation_overflow) {
        p->operations[p->count - 1U].value = value;
        p->operations[p->count - 1U].has_value = true;
    }
}

static void skipped(struct probe *p, const char *name) {
    note(p, name, -1, 0);
    if (!p->operation_overflow) p->operations[p->count - 1U].attempted = false;
}

static void close_owned(struct probe *p, int fd) {
    if (fd < 0) return;
    /* Linux releases a descriptor even when close reports EINTR: never retry. */
    if (close(fd) < 0 && errno != EINTR) p->close_failed = true;
    p->owned_closed++;
}

static int wait_ready(struct probe *p, int fd, short events) {
    struct pollfd item = { .fd = fd, .events = events };
    for (;;) {
        int timeout = remaining_ms(p);
        if (timeout == 0) return -ETIMEDOUT;
        int rc = poll(&item, 1U, timeout);
        if (rc > 0) return (item.revents & POLLNVAL) != 0 ? -EBADF : 0;
        if (rc == 0) return -ETIMEDOUT;
        if (errno != EINTR) return -errno;
    }
}

static bool descriptor_operations(struct probe *p, int fd) {
    int descriptor_flags = fcntl(fd, F_GETFD);
    note_value(p, "fcntl_getfd", descriptor_flags, descriptor_flags < 0 ? errno : 0,
               descriptor_flags >= 0 && (descriptor_flags & FD_CLOEXEC) != 0 ? 1 : 0);
    int flags = fcntl(fd, F_GETFL);
    note(p, "fcntl_getfl", flags, flags < 0 ? errno : 0);
    if (flags >= 0) {
        int rc = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        note(p, "fcntl_nonblock", rc, rc < 0 ? errno : 0);
    } else skipped(p, "fcntl_nonblock");

    int enabled = 1;
    int rc = ioctl(fd, FIONBIO, &enabled);
    note(p, "ioctl_fionbio", rc, rc < 0 ? errno : 0);
    int available = 0;
    rc = ioctl(fd, FIONREAD, &available);
    note_value(p, "ioctl_fionread", rc, rc < 0 ? errno : 0, available);
    int error = 0;
    socklen_t size = sizeof(error);
    rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size);
    note_value(p, "getsockopt_so_error", rc, rc < 0 ? errno : 0, error);
    int type = 0;
    size = sizeof(type);
    rc = getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &size);
    note_value(p, "getsockopt_so_type", rc, rc < 0 ? errno : 0, type);
    int option = 1;
    rc = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &option, sizeof(option));
    note(p, "setsockopt_keepalive", rc, rc < 0 ? errno : 0);
    option = 0; size = sizeof(option);
    rc = getsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &option, &size);
    note_value(p, "getsockopt_keepalive", rc, rc < 0 ? errno : 0, option);
    option = 1;
    rc = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &option, sizeof(option));
    note(p, "setsockopt_tcp_nodelay", rc, rc < 0 ? errno : 0);
    option = 0; size = sizeof(option);
    rc = getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &option, &size);
    note_value(p, "getsockopt_tcp_nodelay", rc, rc < 0 ? errno : 0, option);
    flags = fcntl(fd, F_GETFL);
    note_value(p, "fcntl_verify_nonblock", flags, flags < 0 ? errno : 0,
               flags >= 0 && (flags & O_NONBLOCK) != 0 ? 1 : 0);
    return flags >= 0 && (flags & O_NONBLOCK) != 0;
}

static bool is_loopback(struct probe *p, int fd, bool peer) {
    struct sockaddr_storage address;
    memset(&address, 0, sizeof(address));
    socklen_t length = sizeof(address);
    int rc = peer ? getpeername(fd, (struct sockaddr *)&address, &length) :
                    getsockname(fd, (struct sockaddr *)&address, &length);
    int error = rc < 0 ? errno : 0;
    if (rc == 0) {
        bool matches = false;
        if (address.ss_family == AF_INET && length >= sizeof(struct sockaddr_in)) {
            const struct sockaddr_in *v4 = (const struct sockaddr_in *)&address;
            matches = sucrune_network_probe_loopback_bytes(
                (const unsigned char *)&v4->sin_addr, sizeof(v4->sin_addr)) != 0;
        } else if (address.ss_family == AF_INET6 && length >= sizeof(struct sockaddr_in6)) {
            const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)&address;
            matches = sucrune_network_probe_loopback_bytes(
                (const unsigned char *)&v6->sin6_addr, sizeof(v6->sin6_addr)) != 0;
        }
        if (!matches) error = EPERM;
    }
    note(p, peer ? "peer_loopback" : "listener_loopback", error == 0 ? 0 : -1, error);
    return error == 0;
}

static bool connect_loopback(struct probe *p, int fd, int port) {
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int rc = connect(fd, (const struct sockaddr *)&address, sizeof(address));
    int error = rc < 0 ? errno : 0;
    note(p, "connect_loopback", rc, error);
    if (rc < 0 && error != EINPROGRESS && error != EALREADY && error != EINTR) return false;
    if (rc < 0) {
        int waited = wait_ready(p, fd, POLLOUT);
        note(p, "connect_poll", waited < 0 ? -1 : 0, waited < 0 ? -waited : 0);
        if (waited < 0) return false;
    }
    error = 0;
    socklen_t size = sizeof(error);
    rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size);
    int failure = rc < 0 ? errno : error;
    note(p, "connect_completion", failure == 0 ? 0 : -1, failure);
    return failure == 0;
}

static int accept_loopback(struct probe *p, int fd) {
    int rc = listen(fd, 8);
    note(p, "listen_received", rc, rc < 0 ? errno : 0);
    for (;;) {
        if (remaining_ms(p) == 0) { note(p, "accept4_received", -1, ETIMEDOUT); return -1; }
        int accepted = accept4(fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (accepted >= 0) {
            p->owned_opened++;
            note(p, "accept4_received", accepted, 0);
            return accepted;
        }
        int error = errno;
        if (error == EINTR) continue;
        if (error == EAGAIN || error == EWOULDBLOCK) {
            int waited = wait_ready(p, fd, POLLIN);
            if (waited == 0) continue;
            error = -waited;
        }
        note(p, "accept4_received", -1, error);
        return -1;
    }
}

static bool transfer(struct probe *p, int fd, char *data, bool sending) {
    size_t offset = 0;
    int error = 0;
    while (offset < 4U) {
        if (remaining_ms(p) == 0) { error = ETIMEDOUT; break; }
        ssize_t rc = sending ? send(fd, data + offset, 4U - offset, MSG_DONTWAIT | MSG_NOSIGNAL) :
                               recv(fd, data + offset, 4U - offset, MSG_DONTWAIT);
        if (rc > 0) { offset += (size_t)rc; continue; }
        if (rc == 0) { error = sending ? EIO : ECONNRESET; break; }
        error = errno;
        if (error == EINTR) { error = 0; continue; }
        if (error == EAGAIN || error == EWOULDBLOCK) {
            int waited = wait_ready(p, fd, sending ? POLLOUT : POLLIN);
            if (waited == 0) { error = 0; continue; }
            error = -waited;
        }
        break;
    }
    if (sending) p->sent += offset; else p->received += offset;
    note_value(p, sending ? "send_echo" : "recv_echo", offset == 4U ? 4 : -1,
               offset == 4U ? 0 : error, (int)offset);
    return offset == 4U;
}

static void epoll_readiness(struct probe *p, int fd) {
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    note(p, "epoll_create1", epfd, epfd < 0 ? errno : 0);
    if (epfd < 0) return;
    p->owned_opened++;
    struct epoll_event interest = { .events = EPOLLIN, .data.u64 = UINT64_C(0x53554352554e45) };
    int rc = epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &interest);
    note(p, "epoll_ctl_add_received", rc, rc < 0 ? errno : 0);
    if (rc == 0) {
        struct epoll_event event;
        int error = 0;
        for (;;) {
            int timeout = remaining_ms(p);
            if (timeout == 0) { rc = -1; error = ETIMEDOUT; break; }
            rc = epoll_wait(epfd, &event, 1, timeout);
            if (rc >= 0) { if (rc == 0) { rc = -1; error = ETIMEDOUT; } break; }
            error = errno;
            if (error != EINTR) break;
        }
        if (rc > 0) {
            error = event.data.u64 == interest.data.u64 ? 0 : EIO;
            if (error != 0) rc = -1;
        }
        note(p, "epoll_wait_received", rc, rc < 0 ? error : 0);
    }
    close_owned(p, epfd);
}

static void exchange_echo(struct probe *p, int fd, bool server) {
    char input[4] = {0}, output[4];
    memcpy(output, server ? "PONG" : "PING", sizeof(output));
    if (server) {
        epoll_readiness(p, fd);
        if (!transfer(p, fd, input, false)) return;
        if (memcmp(input, "PING", sizeof(input)) != 0) return;
        p->echo_match = transfer(p, fd, output, true);
    } else {
        if (!transfer(p, fd, output, true)) return;
        epoll_readiness(p, fd);
        p->echo_match = transfer(p, fd, input, false) && memcmp(input, "PONG", sizeof(input)) == 0;
    }
}

static int read_context(struct probe *p, char *context, size_t capacity) {
    context[0] = '\0';
    int fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return errno;
    p->owned_opened++;
    ssize_t count = read(fd, context, capacity - 1U);
    int error = count < 0 ? errno : 0;
    close_owned(p, fd);
    if (count < 0) return error;
    while (count > 0 && (context[count - 1] == '\n' || context[count - 1] == '\0')) count--;
    context[count] = '\0';
    for (size_t i = 0; i < (size_t)count; i++) {
        unsigned char value = (unsigned char)context[i];
        if (value < 32U || value > 126U || value == '"' || value == '\\') context[i] = '?';
    }
    return 0;
}

static void append(struct writer *w, const char *format, ...) {
    if (w->failed) return;
    va_list args;
    va_start(args, format);
    int rc = vsnprintf(w->text + w->used, w->capacity - w->used, format, args);
    va_end(args);
    if (rc < 0 || (size_t)rc >= w->capacity - w->used) { w->failed = true; return; }
    w->used += (size_t)rc;
}

int sucrune_network_probe_run(int mode, int borrowed_fd, int loopback_port,
                             int timeout_ms, char *report, size_t capacity) {
    if (report == NULL || capacity == 0U) return -EINVAL;
    report[0] = '\0';
    if (mode < SUCRUNE_NETWORK_DIRECT || mode > SUCRUNE_NETWORK_ACCEPT ||
        timeout_ms < 1 || timeout_ms > 3000 || (mode != SUCRUNE_NETWORK_DIRECT && borrowed_fd < 0) ||
        (mode == SUCRUNE_NETWORK_CONNECT && (loopback_port < 1 || loopback_port > 65535))) return -EINVAL;
    struct probe p = {0};
    p.started_ns = monotonic_ns();
    if (p.started_ns < 0) return -errno;
    p.deadline_ns = p.started_ns + (int64_t)timeout_ms * INT64_C(1000000);
    char context[256];
    int context_error = read_context(&p, context, sizeof(context));
    if (mode == SUCRUNE_NETWORK_DIRECT) {
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        note(&p, "direct_socket_ipv4_tcp", fd, fd < 0 ? errno : 0);
        if (fd >= 0) { p.owned_opened++; close_owned(&p, fd); }
        fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        note(&p, "direct_socket_ipv6_tcp", fd, fd < 0 ? errno : 0);
        if (fd >= 0) { p.owned_opened++; close_owned(&p, fd); }
    } else {
        bool nonblocking = descriptor_operations(&p, borrowed_fd);
        if (mode == SUCRUNE_NETWORK_CONNECTED) {
            if (is_loopback(&p, borrowed_fd, true)) exchange_echo(&p, borrowed_fd, false);
        }
        else if (!nonblocking) skipped(&p, mode == SUCRUNE_NETWORK_CONNECT ? "connect_loopback" : "accept4_received");
        else if (mode == SUCRUNE_NETWORK_CONNECT) {
            if (connect_loopback(&p, borrowed_fd, loopback_port) && is_loopback(&p, borrowed_fd, true))
                exchange_echo(&p, borrowed_fd, false);
        } else if (is_loopback(&p, borrowed_fd, false)) {
            int accepted = accept_loopback(&p, borrowed_fd);
            if (accepted >= 0) {
                if (is_loopback(&p, accepted, true)) exchange_echo(&p, accepted, true);
                close_owned(&p, accepted);
            }
        }
    }
    int64_t finished = monotonic_ns();
    int64_t elapsed = finished < p.started_ns ? 0 : (finished - p.started_ns) / INT64_C(1000000);
    struct writer w = { .text = report, .capacity = capacity };
    append(&w, "{\"schema_version\":1,\"kind\":\"network_capability\",\"mode\":%d,\"uid\":%lu,\"pid\":%ld,"
               "\"selinux_context\":\"%s\",\"selinux_errno\":%d,\"deadline_ms\":%d,\"operations\":[",
           mode, (unsigned long)getuid(), (long)getpid(), context, context_error, timeout_ms);
    for (size_t i = 0; i < p.count; i++) {
        const struct operation *op = &p.operations[i];
        append(&w, "%s{\"name\":\"%s\",\"attempted\":%s,\"success\":%s,\"rc\":%" PRId64 ",\"errno\":%d",
               i == 0U ? "" : ",", op->name, op->attempted ? "true" : "false",
               op->attempted && op->rc >= 0 ? "true" : "false", op->rc, op->error);
        if (op->has_value) append(&w, ",\"value\":%d", op->value);
        append(&w, "}");
    }
    append(&w, "],\"echo_sent_bytes\":%zu,\"echo_received_bytes\":%zu,\"echo_match\":%s,"
               "\"owned_fds_closed\":%s,\"owned_fd_count\":%u,\"owned_close_count\":%u,"
               "\"elapsed_ms\":%" PRId64 ",\"udp\":\"not_tested\",\"scm_rights\":\"not_tested\"}",
           p.sent, p.received, p.echo_match ? "true" : "false",
           !p.close_failed && p.owned_opened == p.owned_closed ? "true" : "false",
           p.owned_opened, p.owned_closed, elapsed);
    return w.failed || p.operation_overflow ? -ENOSPC : 0;
}
#endif
