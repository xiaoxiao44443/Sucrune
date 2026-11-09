#include "broker_transport.h"
#include "network_broker.h"
#include "pty_broker.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#define RIGHTS_LIMIT 253U
_Static_assert(offsetof(struct sucrune_request, data) == 48U, "request wire header");
_Static_assert(offsetof(struct sucrune_response, data) == 16U, "response wire header");
static int64_t milliseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}
static int deadline(int timeout_ms, int64_t *out) {
    if (timeout_ms < -1) return -EINVAL;
    if (timeout_ms == -1) { *out = -1; return 0; }
    int64_t now = milliseconds(); if (now < 0) return -errno;
    *out = now + timeout_ms; return 0;
}
static int ready(int fd, short events, int64_t end) {
    for (;;) {
        int timeout = -1;
        if (end >= 0) {
            int64_t now = milliseconds(); if (now < 0) return -errno;
            if (now >= end) return -ETIMEDOUT;
            int64_t remaining = end - now; timeout = remaining > INT_MAX ? INT_MAX : (int)remaining;
        }
        struct pollfd pollfd = {.fd = fd, .events = events};
        int result = poll(&pollfd, 1U, timeout);
        if (result < 0 && errno == EINTR) continue;
        if (result < 0) return -errno;
        if (result == 0) return -ETIMEDOUT;
        if ((pollfd.revents & POLLNVAL) != 0) return -EBADF;
        return 0; /* Let send/recv report HUP/ERR precisely. */
    }
}
static int poison(int fd, int error) { (void)shutdown(fd, SHUT_RDWR); return error; }
static int send_packet(int fd, const void *packet, size_t size, int pass_fd, int64_t end) {
    struct iovec iov = {.iov_base = (void *)packet, .iov_len = size};
    union { struct cmsghdr alignment; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control;
    memset(&control, 0, sizeof(control));
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1U};
    if (pass_fd >= 0) {
        message.msg_control = control.bytes; message.msg_controllen = sizeof(control.bytes);
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS; header->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(header), &pass_fd, sizeof(pass_fd));
    }
    for (;;) {
        ssize_t result = sendmsg(fd, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (result >= 0) return (size_t)result == size ? 0 : -EPROTO;
        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) return -errno;
        int error = ready(fd, POLLOUT, end); if (error != 0) return error;
    }
}
static int receive_packet(int fd, void *packet, size_t capacity, size_t *size, int *received_fd,
                          int *optional_right_dropped, int64_t end) {
    struct iovec iov = {.iov_base = packet, .iov_len = capacity};
    union { struct cmsghdr alignment; unsigned char bytes[CMSG_SPACE(sizeof(int) * RIGHTS_LIMIT)]; } control;
    for (;;) {
        struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1U,
            .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)};
        /* The manager's blocking socket can wait for the next request in
         * recvmsg itself. Finite deadlines still require nonblocking I/O. */
        int flags = MSG_CMSG_CLOEXEC | (end < 0 ? 0 : MSG_DONTWAIT);
        ssize_t result = recvmsg(fd, &message, flags);
        if (result < 0) {
            if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) return -errno;
            int error = ready(fd, POLLIN, end); if (error != 0) return error;
            continue;
        }
        int descriptors[RIGHTS_LIMIT]; size_t count = 0U, groups = 0U, offset = 0U;
        int allowed_flags = MSG_CMSG_CLOEXEC | MSG_EOR;
        /* A receiver-side FD limit or security policy can discard SCM_RIGHTS
         * while delivering the complete slot reply. Accept only an entirely
         * missing optional right; partial or malformed ancillary data is fatal. */
        if (optional_right_dropped != NULL && message.msg_controllen == 0)
            allowed_flags |= MSG_CTRUNC;
        int invalid = (message.msg_flags & ~allowed_flags) != 0 || (size_t)result > capacity;
        /* Kernel-created control headers are still parsed by explicit bounds.
         * Unknown ancillary bytes are never treated as FD numbers. */
        while (offset < message.msg_controllen) {
            size_t remaining = message.msg_controllen - offset;
            if (remaining < sizeof(struct cmsghdr)) { invalid = 1; break; }
            struct cmsghdr header; memcpy(&header, control.bytes + offset, sizeof(header));
            if (header.cmsg_len < CMSG_LEN(0U) || header.cmsg_len > remaining) { invalid = 1; break; }
            size_t bytes = header.cmsg_len - CMSG_LEN(0U);
            if (header.cmsg_level == SOL_SOCKET && header.cmsg_type == SCM_RIGHTS) {
                groups++;
                if (bytes == 0U || bytes % sizeof(int) != 0U) invalid = 1;
                size_t rights = bytes / sizeof(int);
                for (size_t i = 0U; i < rights; i++) {
                    int descriptor;
                    memcpy(&descriptor, control.bytes + offset + CMSG_LEN(0U) + i * sizeof(int), sizeof(descriptor));
                    if (count < RIGHTS_LIMIT) descriptors[count++] = descriptor;
                    else { if (descriptor >= 0) (void)close(descriptor); invalid = 1; }
                }
            } else invalid = 1;
            size_t step = CMSG_ALIGN(header.cmsg_len);
            if (step > remaining) {
                if (header.cmsg_len != remaining) invalid = 1;
                offset = message.msg_controllen;
            } else offset += step;
        }
        if (groups > 1U || count > 1U || result == 0) invalid = 1;
        if (count == 1U && descriptors[0] < 0) invalid = 1;
        if (invalid) {
            for (size_t i = 0U; i < count; i++) if (descriptors[i] >= 0) (void)close(descriptors[i]);
            return result == 0 ? -ECONNRESET : -EPROTO;
        }
        if (optional_right_dropped != NULL) *optional_right_dropped = (message.msg_flags & MSG_CTRUNC) != 0;
        *size = (size_t)result; *received_fd = count == 0U ? -1 : descriptors[0]; return 0;
    }
}
static int request_valid(const struct sucrune_request *request, size_t bytes) {
    return bytes >= offsetof(struct sucrune_request, data) && request->magic == SUCRUNE_BROKER_MAGIC &&
        request->size <= SUCRUNE_IO_LIMIT && bytes == offsetof(struct sucrune_request, data) + request->size;
}
static int optional_read_operation(uint32_t operation) {
    return operation == SUCRUNE_BROKER_OPEN_READ || operation == SUCRUNE_BROKER_OPEN_EXEC;
}
static int response_valid(uint32_t operation, const struct sucrune_response *response, size_t bytes, int fd) {
    if (bytes < offsetof(struct sucrune_response, data) || response->magic != SUCRUNE_BROKER_MAGIC ||
        response->size > SUCRUNE_IO_LIMIT || bytes != offsetof(struct sucrune_response, data) + response->size) return 0;
    if (operation==SUCRUNE_BROKER_FORK_SESSION || operation==SUCRUNE_BROKER_MAP_FILE)
        return response->size==0U && ((response->result==0 && fd>=0) || (response->result<0 && fd<0));
    if (optional_read_operation(operation))
        return response->size == 0U && ((response->result < 0 && fd < 0) ||
            (response->result >= SUCRUNE_BROKER_HANDLE_BASE &&
             response->result < SUCRUNE_BROKER_HANDLE_BASE + SUCRUNE_FILE_RESOURCES));
    if (operation==SUCRUNE_PTY_MASTER_OPEN || operation==SUCRUNE_PTY_CONTROL_MASTER)
        return response->size==0U && ((response->result>=0 && response->result<=INT_MAX && fd>=0) || (response->result<0 && fd<0));
    if (!sucrune_net_operation(operation)) return fd < 0;
    if (response->size < SUCRUNE_NET_REPLY_HEADER || sucrune_net_u32(response->data) != SUCRUNE_NET_VERSION) return 0;
    uint32_t count = sucrune_net_u32(response->data + 4U);
    if (count > 1U || count != (fd >= 0 ? 1U : 0U)) return 0;
    if (response->result < 0) return count == 0U && response->size == SUCRUNE_NET_REPLY_HEADER;
    if (operation == SUCRUNE_NET_SOCKET || operation == SUCRUNE_NET_ACCEPT) {
        if (!sucrune_net_token_valid(response->result) || count != 1U) return 0;
        if (operation == SUCRUNE_NET_SOCKET) return response->size == SUCRUNE_NET_REPLY_HEADER;
    } else if (response->result != 0 || count != 0U) return 0;
    if (operation == SUCRUNE_NET_NAME || operation == SUCRUNE_NET_ACCEPT || operation == SUCRUNE_NET_ROUTE) {
        size_t length = response->size - SUCRUNE_NET_REPLY_HEADER;
        const unsigned char *address = response->data + SUCRUNE_NET_REPLY_HEADER;
        return (length == 16U && address[0] == AF_INET && address[1] == 0U) ||
            (length == 28U && address[0] == AF_INET6 && address[1] == 0U);
    }
    return response->size == SUCRUNE_NET_REPLY_HEADER + (operation == SUCRUNE_NET_GETOPT ? 4U : 0U);
}
static int admitted_socket(int fd, uint32_t operation) {
    if (operation==SUCRUNE_BROKER_FORK_SESSION) {
        int type=0; socklen_t length=sizeof(type);
        if (getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&length)!=0) return errno==ENOTSOCK ? -EPROTO : -errno;
        if (length!=sizeof(type) || type!=SOCK_SEQPACKET) return -EPROTO;
        struct sockaddr_storage peer; length=sizeof(peer);
        if (getpeername(fd,(struct sockaddr *)&peer,&length)!=0) return -errno;
        if (length<sizeof(sa_family_t) || peer.ss_family!=AF_UNIX) return -EPROTO;
        int flags=fcntl(fd,F_GETFD);
        return flags<0 ? -errno : (flags&FD_CLOEXEC)!=0 ? 0 : -EPROTO;
    }
    const int options[] = {SO_TYPE, SO_DOMAIN, SO_PROTOCOL}; int values[3];
    for (size_t i = 0U; i < 3U; i++) {
        socklen_t length = sizeof(values[i]);
        if (getsockopt(fd, SOL_SOCKET, options[i], &values[i], &length) != 0) {
            /* A rights payload containing a non-socket violates the protocol.
             * Preserve permission errors: an isolated domain may reject the
             * query on a real socket, which is a capability result, not a codec
             * failure. The caller closes the right and poisons either way. */
            return errno == ENOTSOCK ? -EPROTO : -errno;
        }
        if (length != sizeof(values[i])) return -EPROTO;
    }
    if ((values[1]!=AF_INET && values[1]!=AF_INET6) ||
        !((values[0]==SOCK_STREAM && values[2]==IPPROTO_TCP) ||
          (operation==SUCRUNE_NET_SOCKET && values[0]==SOCK_DGRAM && values[2]==IPPROTO_UDP))) return -EPROTO;
    int descriptor_flags = fcntl(fd, F_GETFD), status = fcntl(fd, F_GETFL);
    if (descriptor_flags < 0 || status < 0) return -errno;
    return (descriptor_flags & FD_CLOEXEC) != 0 && (status & O_NONBLOCK) != 0 ? 0 : -EPROTO;
}
static int receive_response(int fd, uint32_t operation, struct sucrune_response *response,
        int *received_fd, int64_t end) {
    if (received_fd != NULL) *received_fd = -1;
    struct sucrune_response packet; memset(&packet, 0, sizeof(packet));
    size_t bytes = 0U; int right = -1;
    int dropped = 0;
    int error = receive_packet(fd, &packet, sizeof(packet), &bytes, &right,
        optional_read_operation(operation) ? &dropped : NULL, end);
    if (error == 0 && dropped && packet.result < 0) error = -EPROTO;
    if (error == 0 && (!response_valid(operation, &packet, bytes, right) || (right >= 0 && received_fd == NULL))) error = -EPROTO;
    if (error == 0 && right >= 0 && (operation == SUCRUNE_PTY_MASTER_OPEN || operation == SUCRUNE_PTY_CONTROL_MASTER)) {
        int number = -1, flags = fcntl(right, F_GETFD);
        struct stat st;
        if (flags < 0 || fstat(right, &st) < 0) error = -errno;
        else if ((flags & FD_CLOEXEC) == 0 || !S_ISCHR(st.st_mode)) error = -EPROTO;
        else if (ioctl(right, TIOCGPTN, &number) < 0) error = errno == ENOTTY ? -EPROTO : -errno;
        else if (number != packet.result) error = -EPROTO;
    } else if (error == 0 && right >= 0 &&
               (operation == SUCRUNE_BROKER_MAP_FILE || optional_read_operation(operation))) {
        struct stat st;
        int flags = fcntl(right, F_GETFL), descriptor_flags = fcntl(right, F_GETFD);
        if (flags < 0 || descriptor_flags < 0 || fstat(right, &st) < 0) {
            error = -errno;
            if (optional_read_operation(operation) && (error == -EACCES || error == -EPERM)) {
                (void)close(right); right = -1; error = 0;
            }
        }
        else if (!S_ISREG(st.st_mode) || !(descriptor_flags & FD_CLOEXEC) ||
                 (flags & O_PATH) || ((flags & O_ACCMODE) != O_RDONLY &&
                 !(operation == SUCRUNE_BROKER_MAP_FILE && (flags & O_ACCMODE) == O_RDWR))) error = -EPROTO;
    } else if (error == 0 && right >= 0) error = admitted_socket(right,operation);
    if (error != 0) { if (right >= 0) (void)close(right); return poison(fd, error); }
    *response = packet; if (received_fd != NULL) *received_fd = right; return 0;
}
int sucrune_broker_send_request(int fd, const struct sucrune_request *request, int timeout_ms) {
    if (request == NULL || !request_valid(request, offsetof(struct sucrune_request, data) + request->size)) return -EINVAL;
    int64_t end; int error = deadline(timeout_ms, &end); if (error != 0) return error;
    return send_packet(fd, request, offsetof(struct sucrune_request, data) + request->size, -1, end);
}
int sucrune_broker_receive_request(int fd, struct sucrune_request *request, int timeout_ms) {
    if (request == NULL) return -EINVAL;
    int64_t end; int error = deadline(timeout_ms, &end); if (error != 0) return error;
    struct sucrune_request packet; memset(&packet, 0, sizeof(packet));
    size_t bytes = 0U; int right = -1;
    error = receive_packet(fd, &packet, sizeof(packet), &bytes, &right, NULL, end);
    if (error == 0 && (right >= 0 || !request_valid(&packet, bytes))) error = -EPROTO;
    if (right >= 0) (void)close(right);
    if (error != 0) return poison(fd, error);
    *request = packet; return 0;
}
int sucrune_broker_send_response(int fd, uint32_t operation, const struct sucrune_response *response, int send_fd, int timeout_ms) {
    if (response == NULL || !response_valid(operation, response, offsetof(struct sucrune_response, data) + response->size, send_fd)) return -EINVAL;
    int64_t end; int error = deadline(timeout_ms, &end); if (error != 0) return error;
    size_t bytes = offsetof(struct sucrune_response, data) + response->size;
    error = send_packet(fd, response, bytes, send_fd, end);
    if (optional_read_operation(operation) && send_fd >= 0 &&
        (error == -EACCES || error == -EPERM || error == -ETOOMANYREFS || error == -ENOMEM ||
         error == -ENOBUFS || error == -EMFILE || error == -ENFILE)) {
        /* No seqpacket was queued on these errors. Preserve the already-open
         * slot and send the same response without its optional capability. */
        return send_packet(fd, response, bytes, -1, end);
    }
    return error;
}
int sucrune_broker_receive_response(int fd, uint32_t operation, struct sucrune_response *response, int *received_fd, int timeout_ms) {
    if (response == NULL) return -EINVAL;
    int64_t end; int error = deadline(timeout_ms, &end); if (error != 0) return error;
    return receive_response(fd, operation, response, received_fd, end);
}
int sucrune_broker_exchange(int fd, const struct sucrune_request *request,
        struct sucrune_response *response, int *received_fd, int timeout_ms) {
    if (received_fd != NULL) *received_fd = -1;
    if (request == NULL || response == NULL || !request_valid(request, offsetof(struct sucrune_request, data) + request->size)) return -EINVAL;
    int64_t end; int error = deadline(timeout_ms, &end); if (error != 0) return error;
    error = send_packet(fd, request, offsetof(struct sucrune_request, data) + request->size, -1, end);
    if (error != 0) return poison(fd, error);
    /* receive_response already validates ancillary data and publishes the
     * result only on success. Only NET_SOCKET needs another cross-check. */
    if (request->operation != SUCRUNE_NET_SOCKET)
        return receive_response(fd, request->operation, response, received_fd, end);
    struct sucrune_response checked;
    int checked_fd=-1;
    error=receive_response(fd,request->operation,&checked,received_fd!=NULL ? &checked_fd : NULL,end);
    if (error==0 && checked_fd>=0 && request->operation==SUCRUNE_NET_SOCKET) {
        const int options[2]={SO_DOMAIN,SO_TYPE};
        const int64_t expected[2]={request->args[0],request->args[1]&~(int64_t)(SOCK_NONBLOCK|SOCK_CLOEXEC)};
        for (unsigned int i=0U;i<2U;i++) {
            int value=0;socklen_t length=sizeof(value);
            int check=getsockopt(checked_fd,SOL_SOCKET,options[i],&value,&length)==0 ?
                ((length==sizeof(value) && value==expected[i]) ? 0 : -EPROTO) : -errno;
            if (check!=0) {(void)close(checked_fd);return poison(fd,check);}
        }
    }
    if (error==0) {*response=checked;if (received_fd!=NULL) *received_fd=checked_fd;}
    return error;
}
