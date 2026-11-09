#include "guest_sockets.h"
#include <errno.h>
#include <string.h>

static uint16_t little16(const unsigned char *p) { return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8U)); }
static uint16_t big16(const unsigned char *p) { return (uint16_t)(((uint16_t)p[0] << 8U) | (uint16_t)p[1]); }
static uint32_t little32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8U) | ((uint32_t)p[2] << 16U) | ((uint32_t)p[3] << 24U);
}
static uint32_t big32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24U) | ((uint32_t)p[1] << 16U) | ((uint32_t)p[2] << 8U) | (uint32_t)p[3];
}
static void put_little32(unsigned char *p, uint32_t value) {
    for (unsigned int i = 0U; i < 4U; i++) p[i] = (unsigned char)(value >> (i * 8U));
}
static void put_big32(unsigned char *p, uint32_t value) {
    for (unsigned int i = 0U; i < 4U; i++) p[i] = (unsigned char)(value >> ((3U - i) * 8U));
}
int sucrune_socket_address_decode(const void *bytes, size_t length,
                                  struct sucrune_socket_address *address) {
    if (bytes == NULL || address == NULL) return -EFAULT;
    if (length < 2U || length > SUCRUNE_SOCKET_ADDRESS_LIMIT) return -EINVAL;
    const unsigned char *input = bytes;
    struct sucrune_socket_address result = {0};
    result.family = little16(input);
    switch (result.family) {
        case 0: break;
        case 1:
            if (length > 2U + SUCRUNE_SOCKET_UNIX_PATH_LIMIT) return -EINVAL;
            result.unix_length = length - 2U;
            memcpy(result.unix_path, input + 2U, result.unix_length);
            break;
        case 2:
            if (length < 16U) return -EINVAL;
            result.port = big16(input + 2U);
            memcpy(result.address, input + 4U, 4U);
            break;
        case 10:
            if (length < 28U) return -EINVAL;
            result.port = big16(input + 2U); result.flowinfo = big32(input + 4U);
            memcpy(result.address, input + 8U, 16U);
            result.scope_id = little32(input + 24U);
            break;
        default: return -EAFNOSUPPORT;
    }
    *address = result; return 0;
}
int sucrune_socket_address_encode(const struct sucrune_socket_address *address,
                                  void *bytes, size_t capacity, size_t *full_length) {
    if (address == NULL || full_length == NULL || (bytes == NULL && capacity != 0U)) return -EFAULT;
    unsigned char output[SUCRUNE_SOCKET_ADDRESS_LIMIT] = {0};
    output[0] = (unsigned char)address->family; output[1] = (unsigned char)(address->family >> 8U);
    size_t length;
    switch (address->family) {
        case 0: length = 2U; break;
        case 1:
            if (address->unix_length > SUCRUNE_SOCKET_UNIX_PATH_LIMIT) return -EINVAL;
            length = 2U + address->unix_length;
            memcpy(output + 2U, address->unix_path, address->unix_length);
            break;
        case 2:
            length = 16U; memcpy(output + 4U, address->address, 4U); break;
        case 10:
            length = 28U; put_big32(output + 4U, address->flowinfo);
            memcpy(output + 8U, address->address, 16U); put_little32(output + 24U, address->scope_id); break;
        default: return -EAFNOSUPPORT;
    }
    if (address->family == 2U || address->family == 10U) {
        output[2] = (unsigned char)(address->port >> 8U); output[3] = (unsigned char)address->port;
    }
    size_t count = capacity < length ? capacity : length;
    if (count != 0U) memcpy(bytes, output, count);
    *full_length = length; return 0;
}

#if !defined(SUCRUNE_SOCKET_CODEC_ONLY)
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

_Static_assert(AF_UNIX == 1 && SOCK_STREAM == 1 && SOCK_DGRAM == 2 && SOCK_SEQPACKET == 5, "Linux socket ABI");
_Static_assert(SOCK_NONBLOCK == 0x800 && SOCK_CLOEXEC == 0x80000, "Linux socket flags");
_Static_assert(sizeof(int) == 4U, "Linux integer socket option ABI");

int sucrune_socket_pair(struct sucrune_local_io *io, int domain, int type,
                        int protocol, int32_t guest_fds[2]) {
    if (io == NULL || io->ops.reserve == NULL || io->ops.commit == NULL || io->ops.cancel == NULL) return -EINVAL;
    if (guest_fds == NULL) return -EFAULT;
    if (domain != AF_UNIX) return -EAFNOSUPPORT;
    int base = type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (base != SOCK_STREAM && base != SOCK_DGRAM && base != SOCK_SEQPACKET) return -EINVAL;
    if (protocol != 0) return -EPROTONOSUPPORT;
    uintptr_t reservation = 0U;
    int error = io->ops.reserve(io->context, 2U, &reservation);
    if (error != 0) return error < 0 ? error : -EIO;
    int pair[2];
    if (socketpair(AF_UNIX, type | SOCK_CLOEXEC, 0, pair) != 0) {
        error = -errno; io->ops.cancel(io->context, reservation); return error;
    }
    struct sucrune_local_new_fd descriptors[2];
    for (size_t i = 0U; i < 2U; i++) descriptors[i] = (struct sucrune_local_new_fd){
        .host_fd = pair[i], .status_flags = O_RDWR | ((type & SOCK_NONBLOCK) != 0 ? O_NONBLOCK : 0),
        .descriptor_flags = (type & SOCK_CLOEXEC) != 0 ? SUCRUNE_LOCAL_CLOEXEC : 0U};
    int32_t output[2];
    error = io->ops.commit(io->context, reservation, 2U, descriptors, output);
    if (error != 0) {
        (void)close(pair[0]); (void)close(pair[1]); io->ops.cancel(io->context, reservation);
        return error < 0 ? error : -EIO;
    }
    guest_fds[0] = output[0]; guest_fds[1] = output[1]; return 0;
}
static int integer_option(int level, int option) {
    if (level == SOL_SOCKET) switch (option) {
        case SO_TYPE: case SO_ERROR: case SO_ACCEPTCONN: case SO_DOMAIN: case SO_PROTOCOL:
        case SO_RCVBUF: case SO_SNDBUF: case SO_KEEPALIVE: case SO_REUSEADDR:
        case SO_REUSEPORT: case SO_BROADCAST: case SO_OOBINLINE: return 1;
        default: return 0;
    }
    if (level == IPPROTO_TCP) return option == TCP_NODELAY || option == TCP_KEEPIDLE || option == TCP_KEEPINTVL || option == TCP_KEEPCNT;
    return level == IPPROTO_IPV6 && option == IPV6_V6ONLY;
}
int sucrune_socket_get_option(struct sucrune_local_io *io, int32_t guest_fd,
    int level, int option, void *value, size_t capacity, size_t *length) {
    if (io == NULL || io->ops.acquire_many == NULL || io->ops.release_many == NULL) return -EINVAL;
    if (length == NULL || (value == NULL && capacity != 0U)) return -EFAULT;
    if (!integer_option(level, option)) return -ENOPROTOOPT;
    struct sucrune_local_pin pin = {.host_fd = -1};
    int error = io->ops.acquire_many(io->context, &guest_fd, 1U, SUCRUNE_LOCAL_RETAINED_WAIT, &pin);
    if (error != 0) return error < 0 ? error : -EIO;
    /* The local_io callback reports a live resource without a local alias as
     * ENOTSUP. At this socket boundary that resource is not a socket. Keep
     * this translation at acquisition, not at the final result: address
     * normalization deliberately uses ENOTSUP for private UNIX names. */
    if (pin.error != 0) error = pin.error == -ENOTSUP ? -ENOTSOCK : (pin.error < 0 ? pin.error : -EIO);
    else if (pin.host_fd < 0) error = -EBADF;
    else {
        int native = 0; socklen_t size = sizeof(native);
        if (getsockopt(pin.host_fd, level, option, &native, &size) != 0) error = -errno;
        else if (size != sizeof(native)) error = -EIO;
        else {
            unsigned char output[4]; put_little32(output, (uint32_t)native);
            size_t count = capacity < sizeof(output) ? capacity : sizeof(output);
            if (count != 0U) memcpy(value, output, count);
            *length = count;
        }
    }
    io->ops.release_many(io->context, SUCRUNE_LOCAL_RETAINED_WAIT, &pin, 1U);
    return error;
}

static int socket_address_from_host(const struct sockaddr_storage *storage, socklen_t size,
                                    struct sucrune_socket_address *address) {
    if (size < sizeof(storage->ss_family) || size > sizeof(*storage)) return -EIO;
    struct sucrune_socket_address normalized = {0};
    if (storage->ss_family == AF_UNIX) {
        if (size != offsetof(struct sockaddr_un, sun_path)) return -ENOTSUP;
        normalized.family = 1U;
    } else if (storage->ss_family == AF_INET) {
        if (size != sizeof(struct sockaddr_in)) return -EIO;
        struct sockaddr_in native;
        memcpy(&native, storage, sizeof(native));
        normalized.family = 2U;
        normalized.port = ntohs(native.sin_port);
        memcpy(normalized.address, &native.sin_addr, sizeof(native.sin_addr));
    } else if (storage->ss_family == AF_INET6) {
        if (size != sizeof(struct sockaddr_in6)) return -EIO;
        struct sockaddr_in6 native;
        memcpy(&native, storage, sizeof(native));
        normalized.family = 10U;
        normalized.port = ntohs(native.sin6_port);
        normalized.flowinfo = ntohl(native.sin6_flowinfo);
        normalized.scope_id = native.sin6_scope_id;
        memcpy(normalized.address, &native.sin6_addr, sizeof(native.sin6_addr));
    } else return -EAFNOSUPPORT;
    *address = normalized;
    return 0;
}

int sucrune_socket_get_name(struct sucrune_local_io *io, int32_t guest_fd,
    int peer, void *value, size_t capacity, size_t *length) {
    if (io == NULL || io->ops.acquire_many == NULL || io->ops.release_many == NULL) return -EINVAL;
    if (peer != 0 && peer != 1) return -EINVAL;
    if (length == NULL || (value == NULL && capacity != 0U)) return -EFAULT;
    struct sucrune_local_pin pin = {.host_fd = -1};
    int error = io->ops.acquire_many(io->context, &guest_fd, 1U, SUCRUNE_LOCAL_RETAINED_WAIT, &pin);
    if (error != 0) return error < 0 ? error : -EIO;
    /* ENOTSUP in a pin means no local alias, as specified by local_io. The
     * later named-UNIX normalization error must remain ENOTSUP. */
    if (pin.error != 0) error = pin.error == -ENOTSUP ? -ENOTSOCK : (pin.error < 0 ? pin.error : -EIO);
    else if (pin.host_fd < 0) error = -EBADF;
    else {
        struct sockaddr_storage native;
        memset(&native, 0, sizeof(native));
        socklen_t size = sizeof(native);
        int result = peer ? getpeername(pin.host_fd, (struct sockaddr *)&native, &size) :
                            getsockname(pin.host_fd, (struct sockaddr *)&native, &size);
        if (result != 0) error = -errno;
        else {
            struct sucrune_socket_address address;
            error = socket_address_from_host(&native, size, &address);
            if (error == 0) error = sucrune_socket_address_encode(&address, value, capacity, length);
        }
    }
    io->ops.release_many(io->context, SUCRUNE_LOCAL_RETAINED_WAIT, &pin, 1U);
    return error;
}
#endif
