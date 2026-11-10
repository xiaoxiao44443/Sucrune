#ifndef SUCRUNE_GUEST_NETWORK_H
#define SUCRUNE_GUEST_NETWORK_H
#include "network_broker.h"
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

/* One canonical local descriptor and a manager token per open description.
 * The guest FD table owns aliases separately. All calls are serialized by the
 * caller's state lock, including every complete file/network transaction. */
#define SUCRUNE_UDP_BOUND 1
#define SUCRUNE_UDP_CONNECTED 2
struct sucrune_guest_network_entry { int fd, type, udp_state, echo_domain; int64_t token; };
struct sucrune_guest_network {
    int broker;
    unsigned int count, peak;
    struct sucrune_guest_network_entry entries[SUCRUNE_NET_RESOURCE_LIMIT];
};
void sucrune_guest_network_init(struct sucrune_guest_network *network, int broker);
int sucrune_guest_network_contains(const struct sucrune_guest_network *network, int fd);
int sucrune_guest_network_type(const struct sucrune_guest_network *network, int fd);
uint64_t sucrune_guest_network_token(const struct sucrune_guest_network *network, int fd);
/* Fresh child runner only. Success adopts fd. Commit validates every retained
 * socket identity against the child broker before dropping unkept slots. */
int sucrune_guest_network_restore_tcp(struct sucrune_guest_network *network, int fd, uint64_t token);
int sucrune_guest_network_commit_exec(struct sucrune_guest_network *network);
/* Rights observed on this open description; no implicit kernel autobind via
 * send(NULL), generic write/writev etc. Unconnected sends require ROUTE. */
int sucrune_guest_network_udp_state(const struct sucrune_guest_network *network, int fd);
/* Success adopts the transferred descriptor and returns it, never a guest FD.
 * Caller must preflight guest capacity and publish a guest descriptor; if
 * publication fails, release the returned canonical FD through this module. */
int sucrune_guest_network_socket(struct sucrune_guest_network *network, int domain, int type, int protocol);
int sucrune_guest_network_echo_domain(const struct sucrune_guest_network *network, int fd);
/* For echo only. The caller holds its state lock through both staging and the
 * send RPC. Receives use one private payload iovec and room for 28 address bytes. */
ssize_t sucrune_guest_network_echo_message(struct sucrune_guest_network *network, int fd,
    int receiving, struct msghdr *message, int flags);
int sucrune_guest_network_accept(struct sucrune_guest_network *network, int fd, int flags,
    void *address, size_t capacity, size_t *length);
/* Last guest alias owns release. This consumes the canonical FD even when
 * remote release fails; manager channel EOF remains the final cleanup barrier. */
int sucrune_guest_network_release(struct sucrune_guest_network *network, int fd);
int sucrune_guest_network_address(struct sucrune_guest_network *network, int fd,
    int connect_operation, const void *address, size_t length);
/* source=0 returns a PRIVATE kernel sockaddr, never guest copyout. source=1
 * translates a received kernel sockaddr into the normalized guest source. */
int sucrune_guest_network_route(struct sucrune_guest_network *, int fd, int source,
    const void *address, size_t length, void *output, size_t capacity, size_t *output_length);
int sucrune_guest_network_control(struct sucrune_guest_network *network, int fd,
    uint32_t operation, int64_t argument, int64_t option, const void *input, size_t input_length,
    void *output, size_t capacity, size_t *output_length);
#endif
