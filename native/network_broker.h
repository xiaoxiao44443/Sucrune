#ifndef SUCRUNE_NETWORK_BROKER_H
#define SUCRUNE_NETWORK_BROKER_H
#include "workspace_broker.h"
#include <stdint.h>

#define SUCRUNE_NET_VERSION 1U
#define SUCRUNE_NET_REPLY_HEADER 8U
#define SUCRUNE_NET_RESOURCE_LIMIT 64U
#define SUCRUNE_NET_SOCKET 0x53551001U
#define SUCRUNE_NET_BIND 0x53551002U
#define SUCRUNE_NET_CONNECT 0x53551003U
#define SUCRUNE_NET_LISTEN 0x53551004U
#define SUCRUNE_NET_ACCEPT 0x53551005U
#define SUCRUNE_NET_NAME 0x53551006U
#define SUCRUNE_NET_GETOPT 0x53551007U
#define SUCRUNE_NET_SETOPT 0x53551008U
#define SUCRUNE_NET_SHUTDOWN 0x53551009U
#define SUCRUNE_NET_RELEASE 0x5355100aU
#define SUCRUNE_NET_ROUTE 0x5355100bU
#define SUCRUNE_NET_EXEC_KEEP 0x5355100cU
#define SUCRUNE_NET_ECHO_SOCKET 0x5355100dU
#define SUCRUNE_NET_ECHO_SEND 0x5355100eU
#define SUCRUNE_NET_ECHO_SOURCE_BYTES 28U
#define SUCRUNE_NET_ECHO_PACKET_LIMIT 65535U
/* Private child-session exec commit. args={count,0,0,version}, followed by
 * count little-endian {token, socket st_dev, socket st_ino} u64 triples. */
#define SUCRUNE_NET_KEEP_BYTES 24U
#define SUCRUNE_NETWORK_NONE 0
#define SUCRUNE_NETWORK_LOOPBACK 1
#define SUCRUNE_NETWORK_OUTBOUND 2
#define SUCRUNE_NET_TOKEN_PREFIX UINT64_C(0x4e54000000000000)
#define SUCRUNE_NET_TOKEN_MASK UINT64_C(0xffff000000000000)
#define SUCRUNE_NET_GENERATION_MAX UINT64_C(0x3ffffffffff)
/* Token = prefix | (nonzero 42-bit generation << 6) | slot[0..63].
 * A saturated generation slot is never reused; tokens are never wrapped. */

/* Private v1 wire contract, independent of Linux syscall numbers:
 * all requests: reserved=0, args[3]=1. SOCKET args={domain,type,protocol,1};
 * other operations args[0]=typed generation token. BIND/CONNECT args[1]=
 * exact normalized ARM64 sockaddr length, args[2]=0, data=sockaddr. LISTEN
 * args[1]=backlog (0..128); ACCEPT args[1]=SOCK_NONBLOCK with optional CLOEXEC;
 * NAME args[1]=0(local)/1(peer); GETOPT/SETOPT args[1]=level,args[2]=option,
 * SETOPT data=one little-endian int32. SHUTDOWN args[1]=SHUT_RD/WR/RDWR.
 * RELEASE has args[1..2]=0. All unmentioned fields/payloads must be zero.
 * SOCKET/ACCEPT success result=positive token and exactly one SCM_RIGHTS FD.
 * Other success result=0; errors are -errno with no FD. Every network reply
 * data starts with {u32le version=1,u32le fd_count}; optional bytes follow:
 * ACCEPT/NAME: full normalized sockaddr; GETOPT: int32le. Other replies: none.
 * ROUTE args={token,direction,address_length,1}: 0 translates a guest UDP
 * destination to a private worker destination; 1 translates the actual packet
 * source to guest form. Reply is a normalized address like NAME. Direction 0
 * is never copied to guest memory. Physical sockets are always nonblocking and
 * CLOEXEC. TCP still requires SOCK_NONBLOCK. A plain UDP constructor is valid
 * so the guest can set O_NONBLOCK later (as c-ares does). Guest fcntl flags
 * are distinct from this physical invariant; logical blocking I/O has not
 * been implemented. OUTBOUND permits outbound TCP unicast, managed DNS
 * and kernel ICMP echo datagrams. UDP and binds/listeners remain restricted.
 * Loopback is device-shared, not a project network namespace/security boundary.
 */
/* ECHO_SOCKET has the same request shape as SOCKET. Its single right is an
 * unnamed, connected nonblocking AF_UNIX/SOCK_SEQPACKET data channel. Android
 * keeps the physical ICMP socket in the ordinary app domain. For ECHO_SEND,
 * queue one packet on the channel, then send {token,flags,0,version} with a
 * sockaddr (empty for a connected socket). A successful reply adds a u32 byte
 * count. Incoming records contain a zero-padded sockaddr then the ICMP bytes;
 * a 28-byte AF_UNSPEC record stores a positive errno at offset 4. */
struct sucrune_net_slot { int fd, domain, type, protocol, bound, dns_registered, network_selected, echo_peer; uint64_t generation; };
/* Optional manager-only hooks. select_socket selects the snapshotted Android
 * Network before an external connect. dns_add registers an already-bound local
 * socket with the proxy before any guest data or connect; dns_remove revokes
 * that generation before closing. Hook context stays alive through destroy. */
struct sucrune_network_hooks {
    void *context;
    int (*select_socket)(void *, int fd);
    int (*dns_add)(void *, int type, int fd, uint64_t token);
    void (*dns_remove)(void *, uint64_t token);
    uint16_t dns_port;
};
struct sucrune_network_broker {
    struct sucrune_net_slot slots[SUCRUNE_NET_RESOURCE_LIMIT];
    /* Manager-only socket table. The root stays pinned until detach. */
    struct sucrune_network_broker *scope_next;
    uint64_t root_device, root_inode;
    uint64_t visible_slots;
    int scope_attached;
    unsigned int count, peak;
    unsigned int echo_count;
    unsigned char *echo_packet;
    int policy, fork_session, build_profile;
    unsigned int total_resource_limit;
    struct sucrune_network_hooks hooks;
};
int sucrune_net_operation(uint32_t operation);
int sucrune_net_token_valid(int64_t token);
uint32_t sucrune_net_u32(const unsigned char *bytes);
void sucrune_net_put_u32(unsigned char *bytes, uint32_t value);
int sucrune_network_init(struct sucrune_network_broker *network, int policy);
int sucrune_network_attach_workspace(struct sucrune_network_broker *, int root);
int sucrune_network_proc_open(struct sucrune_network_broker *, int table, uint32_t guest_uid);
int sucrune_network_set_hooks(struct sucrune_network_broker *, const struct sucrune_network_hooks *);
void sucrune_network_destroy(struct sucrune_network_broker *network);
int sucrune_network_fork_connected(struct sucrune_network_broker *child,const struct sucrune_network_broker *parent);
/* Blocks until the control channel is ready. While echo sockets exist,
 * opportunistically forwards real kernel replies to their data channels. */
int sucrune_network_wait_control(struct sucrune_network_broker *network, int control_fd);
/* Serialized manager dispatcher. other_resources counts open file resources;
 * files share the selected total budget, with at most 64 network slots. send_fd borrows a canonical FD
 * through the sendmsg call. ECHO_SOCKET returns a new data endpoint instead;
 * its caller closes that endpoint after sending the reply, including on error. */
void sucrune_network_dispatch(struct sucrune_network_broker *network,
    unsigned int other_resources, const struct sucrune_request *request,
    struct sucrune_response *response, int *send_fd);
#endif
