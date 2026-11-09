#ifndef SUCRUNE_GUEST_SOCKETS_H
#define SUCRUNE_GUEST_SOCKETS_H

#include "guest_local_io.h"
#include <stddef.h>
#include <stdint.h>

#define SUCRUNE_SOCKET_ADDRESS_LIMIT 128U
#define SUCRUNE_SOCKET_UNIX_PATH_LIMIT 108U

/* Normalized values: port/flowinfo/scope_id are host-order integers. IPv4 uses
 * address[0..3], IPv6 uses all 16 bytes. UNIX names are counted bytes: abstract
 * names and embedded NULs must never be converted into C strings. Parsing a
 * UNIX address grants no authority to open a host namespace path. */
struct sucrune_socket_address {
    uint16_t family, port;
    uint32_t flowinfo, scope_id;
    unsigned char address[16];
    size_t unix_length;
    unsigned char unix_path[SUCRUNE_SOCKET_UNIX_PATH_LIMIT];
};

/* Linux ARM64 little-endian sockaddr family, network-order port/flowinfo,
 * little-endian IPv6 scope. AF_UNSPEC=0, AF_UNIX=1, AF_INET=2, AF_INET6=10.
 * decode rejects short/oversized/unknown input without changing output.
 * encode follows getsockname semantics: copies min(capacity, full_length),
 * returns full_length separately, accepts NULL output only with capacity=0.
 * All buffers are host-validated/normalized; no raw guest pointers are used. */
int sucrune_socket_address_decode(const void *bytes, size_t length,
                                  struct sucrune_socket_address *address);
int sucrune_socket_address_encode(const struct sucrune_socket_address *address,
                                  void *bytes, size_t capacity, size_t *full_length);

/* Foundational local IPC only: domain must be AF_UNIX and protocol zero.
 * STREAM/DGRAM/SEQPACKET with Linux NONBLOCK/CLOEXEC are accepted. Host FDs are
 * always CLOEXEC; guest CLOEXEC remains per-entry metadata. Existing local_io
 * callbacks reserve two slots and atomically publish/roll back both FDs. */
int sucrune_socket_pair(struct sucrune_local_io *io, int domain, int type,
                        int protocol, int32_t guest_fds[2]);

/* Read selected integer socket options through a retained FD, never exposing
 * a host descriptor or an unnormalized kernel buffer. Whitelist includes
 * SOL_SOCKET SO_TYPE/SO_ERROR/SO_ACCEPTCONN/SO_DOMAIN/SO_PROTOCOL, buffer sizes,
 * reuse/broadcast/keepalive/OOB-inline; TCP NODELAY/keepalive settings and
 * IPV6_V6ONLY. Unsupported options return ENOPROTOOPT before acquisition.
 * Unlike sockaddr encoding, returned length is min(capacity,4), matching
 * Linux integer getsockopt truncation. No automatic EINTR retry. */
int sucrune_socket_get_option(struct sucrune_local_io *io, int32_t guest_fd,
    int level, int option, void *value, size_t capacity, size_t *length);

/* Queries a retained socket description: peer=0 for getsockname, peer=1 for
 * getpeername. Encodes the actual kernel address as Linux ARM64 sockaddr bytes.
 * Success copies min(capacity, full_length) and returns full_length in length;
 * NULL value is valid only with capacity=0. Failures leave both outputs intact.
 * Unnamed AF_UNIX addresses encode as the two-byte family. Named/abstract UNIX
 * addresses return ENOTSUP until a project namespace translation exists: host
 * paths and abstract names must never be exposed by this generic helper.
 * Other supported families are AF_INET/AF_INET6. No raw guest pointers or broker
 * handles are accepted; acquire_many supplies a retained local FD or an error. */
int sucrune_socket_get_name(struct sucrune_local_io *io, int32_t guest_fd,
    int peer, void *value, size_t capacity, size_t *length);

#endif
