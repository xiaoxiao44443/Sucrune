#include "network_broker.h"
#include "guest_sockets.h"
#if !defined(SUCRUNE_NETWORK_WIRE_ONLY)
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/memfd.h>
#include <unistd.h>
#endif

uint32_t sucrune_net_u32(const unsigned char *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8U) |
        ((uint32_t)bytes[2] << 16U) | ((uint32_t)bytes[3] << 24U);
}
void sucrune_net_put_u32(unsigned char *bytes, uint32_t value) {
    for (unsigned int i = 0U; i < 4U; i++) bytes[i] = (unsigned char)(value >> (i * 8U));
}
int sucrune_net_operation(uint32_t operation) {
    return operation >= SUCRUNE_NET_SOCKET && operation <= SUCRUNE_NET_ECHO_SEND;
}
int sucrune_net_token_valid(int64_t token) {
    uint64_t value = (uint64_t)token;
    return (value & SUCRUNE_NET_TOKEN_MASK) == SUCRUNE_NET_TOKEN_PREFIX &&
        ((value >> 6U) & SUCRUNE_NET_GENERATION_MAX) != 0U;
}
#if !defined(SUCRUNE_NETWORK_WIRE_ONLY)
#include "network_proc.inc"
int sucrune_network_init(struct sucrune_network_broker *network, int policy) {
    if (network == NULL) return -EINVAL;
    if (policy != SUCRUNE_NETWORK_NONE && policy != SUCRUNE_NETWORK_LOOPBACK && policy != SUCRUNE_NETWORK_OUTBOUND) return -EINVAL;
    memset(network, 0, sizeof(*network)); network->policy = policy;
    network->total_resource_limit = SUCRUNE_DEFAULT_FILE_RESOURCES;
    for (size_t i = 0U; i < SUCRUNE_NET_RESOURCE_LIMIT; i++) network->slots[i].fd = -1;
    return 0;
}
int sucrune_network_set_hooks(struct sucrune_network_broker *network, const struct sucrune_network_hooks *hooks) {
    if (network==NULL || hooks==NULL || network->policy!=SUCRUNE_NETWORK_OUTBOUND ||
        (hooks->dns_port==0U ? (hooks->dns_add!=NULL || hooks->dns_remove!=NULL) :
         (hooks->dns_add==NULL || hooks->dns_remove==NULL))) return -EINVAL;
    if (network->count!=0U) return -EBUSY;
    network->hooks=*hooks;return 0;
}
static uint64_t slot_token(const struct sucrune_network_broker *network, const struct sucrune_net_slot *slot) {
    return SUCRUNE_NET_TOKEN_PREFIX | (slot->generation<<6U) | (uint64_t)(slot-network->slots);
}
static void revoke_dns(struct sucrune_network_broker *network, struct sucrune_net_slot *slot) {
    if (slot->dns_registered) {network->hooks.dns_remove(network->hooks.context,slot_token(network,slot));slot->dns_registered=0;}
}
static int release_slot(struct sucrune_network_broker *network, struct sucrune_net_slot *slot) {
    set_slot_visible(network, slot, 0);
    revoke_dns(network, slot);
    if (slot->echo_peer >= 0) {
        (void)close(slot->echo_peer);
        slot->echo_peer = -1;
        if (--network->echo_count == 0U) {
            free(network->echo_packet);
            network->echo_packet = NULL;
        }
    }
    int result = close(slot->fd) == 0 ? 0 : -errno;
    slot->fd = -1;
    network->count--;
    return result;
}
void sucrune_network_destroy(struct sucrune_network_broker *network) {
    detach_workspace(network);
    /* A workspace can unwind before setup_network initialized the slot array. */
    if (network->count == 0U) return;
    for (size_t i = 0U; i < SUCRUNE_NET_RESOURCE_LIMIT; i++) {
        if (network->slots[i].fd >= 0) (void)release_slot(network, &network->slots[i]);
    }
}
static int free_slot(const struct sucrune_network_broker *network, unsigned int other) {
    if (network->count >= SUCRUNE_NET_RESOURCE_LIMIT || other >= network->total_resource_limit ||
        network->count >= network->total_resource_limit - other) return -EMFILE;
    for (unsigned int i = 0U; i < SUCRUNE_NET_RESOURCE_LIMIT; i++)
        if (network->slots[i].fd < 0 && network->slots[i].generation < SUCRUNE_NET_GENERATION_MAX) return (int)i;
    return -EOVERFLOW;
}
static struct sucrune_net_slot *lookup(struct sucrune_network_broker *network, int64_t token) {
    if (!sucrune_net_token_valid(token)) return NULL;
    struct sucrune_net_slot *slot = &network->slots[(uint64_t)token & UINT64_C(63)];
    uint64_t generation = ((uint64_t)token >> 6U) & SUCRUNE_NET_GENERATION_MAX;
    return slot->fd >= 0 && slot->generation == generation ? slot : NULL;
}
static int loopback(const struct sucrune_socket_address *address);
static int forkable_socket(const struct sucrune_network_broker *network,const struct sucrune_net_slot *slot) {
    if (slot->dns_registered) return 0;
    struct sockaddr_storage actual;
    socklen_t length=sizeof(actual);
    if (slot->type==SOCK_STREAM) {
        if (getpeername(slot->fd,(struct sockaddr *)&actual,&length)==0)
            return actual.ss_family==slot->domain &&
                ((actual.ss_family==AF_INET && length==sizeof(struct sockaddr_in)) ||
                 (actual.ss_family==AF_INET6 && length==sizeof(struct sockaddr_in6)));
        if (errno!=ENOTCONN || !slot->bound) return 0;
        int listening=0;
        socklen_t option_length=sizeof(listening);
        if (getsockopt(slot->fd,SOL_SOCKET,SO_ACCEPTCONN,&listening,&option_length)!=0 ||
            option_length!=sizeof(listening) || !listening) return 0;
    } else {
        /* Only the build profile's bound, unconnected loopback datagram socket
         * may be carried through fork for close/dup before the next exec. */
        if (slot->protocol!=IPPROTO_UDP || !network->build_profile ||
            network->policy!=SUCRUNE_NETWORK_LOOPBACK || !slot->bound || slot->network_selected) return 0;
        if (getpeername(slot->fd,(struct sockaddr *)&actual,&length)==0 || errno!=ENOTCONN) return 0;
    }
    length=sizeof(actual);
    struct sucrune_socket_address local;
    return getsockname(slot->fd,(struct sockaddr *)&actual,&length)==0 && actual.ss_family==slot->domain &&
        sucrune_socket_address_decode(&actual,length,&local)==0 && local.port!=0U && loopback(&local);
}
int sucrune_network_fork_connected(struct sucrune_network_broker *child,const struct sucrune_network_broker *parent) {
    if(child==NULL || parent==NULL || child==parent || child->count!=0 || child->policy!=parent->policy) return -EINVAL;
    int error=0;
    for(size_t i=0;i<SUCRUNE_NET_RESOURCE_LIMIT;i++) {
        const struct sucrune_net_slot *src=&parent->slots[i];
        child->slots[i].generation=src->generation;
        if(src->fd<0) continue;
        if(!forkable_socket(parent,src)) {error=-EOPNOTSUPP;break;}
        int fd=fcntl(src->fd,F_DUPFD_CLOEXEC,3);
        if(fd<0) {error=-errno;break;}
        child->slots[i]=*src;child->slots[i].fd=fd;child->count++;
        set_slot_visible(child, &child->slots[i], 1);
    }
    if(error!=0) {sucrune_network_destroy(child);return error;}
    child->peak=child->count;child->fork_session=1;
    return 0;
}
static uint64_t get_u64(const unsigned char *data) {
    return sucrune_net_u32(data)|((uint64_t)sucrune_net_u32(data+4U)<<32U);
}
static int keep_after_exec(struct sucrune_network_broker *network,const struct sucrune_request *request) {
    if(!network->fork_session) return -EPERM;
    int64_t count=request->args[0];
    if(count<0 || count>SUCRUNE_NET_RESOURCE_LIMIT || request->args[1]!=0 || request->args[2]!=0 ||
       request->size!=(uint32_t)count*SUCRUNE_NET_KEEP_BYTES) return -EINVAL;
    uint64_t mask=0U;
    for(unsigned int i=0U;i<(unsigned int)count;i++) {
        const unsigned char *row=request->data+i*SUCRUNE_NET_KEEP_BYTES;
        uint64_t token=get_u64(row),bit=UINT64_C(1)<<(token&63U);
        if((mask&bit)!=0U) return -EINVAL;
        struct sucrune_net_slot *slot=lookup(network,(int64_t)token);
        if(slot==NULL || slot->type!=SOCK_STREAM || slot->dns_registered) return -EBADF;
        struct stat st;
        if(fstat(slot->fd,&st)!=0) return -errno;
        if(!S_ISSOCK(st.st_mode) || (uint64_t)st.st_dev!=get_u64(row+8) || (uint64_t)st.st_ino!=get_u64(row+16)) return -EPROTO;
        mask|=bit;
    }
    for(unsigned int i=0U;i<SUCRUNE_NET_RESOURCE_LIMIT;i++) {
        struct sucrune_net_slot *slot=&network->slots[i];
        if(slot->fd<0 || (mask&(UINT64_C(1)<<i))!=0U) continue;
        (void)release_slot(network,slot);
    }
    return 0;
}
static int64_t adopt(struct sucrune_network_broker *network, int index, int fd, int domain, int type, int protocol) {
    struct sucrune_net_slot *slot = &network->slots[index];
    slot->generation++; slot->fd=fd;slot->domain=domain;slot->type=type;slot->protocol=protocol;slot->bound=0;
    slot->dns_registered=0;slot->network_selected=0;
    slot->echo_peer=-1;
    set_slot_visible(network, slot, 1);
    network->count++;
    if (network->count > network->peak) network->peak = network->count;
    return (int64_t)(SUCRUNE_NET_TOKEN_PREFIX | (slot->generation << 6U) | (unsigned int)index);
}
static int ensure_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) return -errno;
    return (flags & O_NONBLOCK) != 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 ? 0 : -errno;
}
static int loopback(const struct sucrune_socket_address *address) {
    static const unsigned char ipv4[4] = {127, 0, 0, 1};
    static const unsigned char ipv6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    static const unsigned char mapped[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1};
    if (address->family == AF_INET) return memcmp(address->address, ipv4, sizeof(ipv4)) == 0;
    return address->family == AF_INET6 && address->scope_id == 0U && address->flowinfo == 0U &&
        (memcmp(address->address, ipv6, sizeof(ipv6)) == 0 || memcmp(address->address, mapped, sizeof(mapped)) == 0);
}
static int unicast4(const unsigned char *ip) {
    return ip[0]!=0U && ip[0]!=127U && ip[0]<224U && !(ip[0]==169U && ip[1]==254U);
}
static int outbound_unicast(const struct sucrune_socket_address *address) {
    if (address->family==AF_INET) return unicast4(address->address);
    const unsigned char *ip=address->address;
    static const unsigned char zero[12]={0};
    if (address->scope_id!=0U || address->flowinfo!=0U || ip[0]==255U ||
        (ip[0]==0xfeU && (ip[1]&0xc0U)==0x80U)) return 0;
    if (memcmp(ip,zero,10U)==0 && ip[10]==255U && ip[11]==255U) return unicast4(ip+12U);
    return memcmp(ip,zero,12U)!=0; /* Reject unspecified, loopback, IPv4-compatible forms. */
}
static int virtual_dns(const struct sucrune_socket_address *address) {
    static const unsigned char dns[4]={127U,0U,0U,53U};
    return address->family==AF_INET && address->port==53U && memcmp(address->address,dns,4U)==0;
}
static int physical_dns(const struct sucrune_network_broker *network, const struct sucrune_socket_address *address) {
    return network->hooks.dns_port!=0U && address->port==network->hooks.dns_port && loopback(address);
}
/* First authorized UDP send/connect must not let the kernel implicitly bind
 * the transferred socket to every interface. A failed authorization has no
 * bind side effect. Existing wildcard/external bindings are not adopted. */
static int ensure_udp_loopback_source(struct sucrune_net_slot *slot,const struct sucrune_socket_address *destination) {
    if (slot->type!=SOCK_DGRAM) return 0;
    struct sockaddr_storage actual;memset(&actual,0,sizeof(actual));socklen_t length=sizeof(actual);
    if (getsockname(slot->fd,(struct sockaddr *)&actual,&length)!=0) return -errno;
    if (slot->domain==AF_INET && actual.ss_family==AF_INET && length==sizeof(struct sockaddr_in)) {
        struct sockaddr_in local;memcpy(&local,&actual,sizeof(local));
        if (local.sin_port!=0U) return local.sin_addr.s_addr==htonl(INADDR_LOOPBACK) ? 0 : -EACCES;
        local.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        return bind(slot->fd,(struct sockaddr *)&local,sizeof(local))==0 ? 0 : -errno;
    }
    if (slot->domain==AF_INET6 && actual.ss_family==AF_INET6 && length==sizeof(struct sockaddr_in6)) {
        struct sockaddr_in6 local;memcpy(&local,&actual,sizeof(local));
        if (local.sin6_port!=0U) {
            struct sucrune_socket_address normalized={.family=AF_INET6,.port=ntohs(local.sin6_port),
                .scope_id=local.sin6_scope_id,.flowinfo=ntohl(local.sin6_flowinfo)};
            memcpy(normalized.address,&local.sin6_addr,16U);
            return loopback(&normalized) ? 0 : -EACCES;
        }
        /* IPv6 ::1 and IPv4-mapped 127.0.0.1 need different source addresses. */
        memcpy(&local.sin6_addr,destination->address,16U);
        return bind(slot->fd,(struct sockaddr *)&local,sizeof(local))==0 ? 0 : -errno;
    }
    return -EAFNOSUPPORT;
}
static int register_dns(struct sucrune_network_broker *network, struct sucrune_net_slot *slot) {
    if (slot->dns_registered) return 0;
    if (network->hooks.dns_add==NULL || slot->domain!=AF_INET) return -ENETUNREACH;
    int options[]={SO_REUSEADDR,SO_REUSEPORT};
    for (size_t i=0U;i<2U;i++) {
        int value=0;socklen_t size=sizeof(value);
        if (getsockopt(slot->fd,SOL_SOCKET,options[i],&value,&size)!=0) return -errno;
        if (size!=sizeof(value) || value!=0) return -EACCES;
    }
    struct sockaddr_in local;memset(&local,0,sizeof(local));socklen_t size=sizeof(local);
    if (getsockname(slot->fd,(struct sockaddr *)&local,&size)!=0) return -errno;
    if (size!=sizeof(local) || local.sin_family!=AF_INET) return -EPROTO;
    if (local.sin_port==0U) {
        local.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        if (bind(slot->fd,(struct sockaddr *)&local,sizeof(local))!=0) return -errno;
    }
    int error=network->hooks.dns_add(network->hooks.context,slot->type,slot->fd,slot_token(network,slot));
    if (error==0) slot->dns_registered=1;
    return error;
}
static int select_outbound(struct sucrune_network_broker *network, struct sucrune_net_slot *slot) {
    if (!slot->network_selected && network->hooks.select_socket!=NULL) {
        int error=network->hooks.select_socket(network->hooks.context,slot->fd);
        if (error!=0) return error;
        slot->network_selected=1;
    }
    return 0;
}
/* Translate only values from normalized bytes. source=1 must never return the
 * private proxy address. Connections and unconnected datagrams use one policy. */
static int route_address(struct sucrune_network_broker *network, struct sucrune_net_slot *slot,
        struct sucrune_socket_address *address, int binding, int source) {
    int echo = slot->protocol == IPPROTO_ICMP || slot->protocol == IPPROTO_ICMPV6;
    if (echo) {
        /* Linux datagram ping sockets can only exchange ICMP echo, never raw IP.
         * sockaddr ports describe the local echo identifier, not a TCP/UDP
         * endpoint. In particular no DNS proxy or UDP source bind applies. */
        if (loopback(address)) return 0;
        if (binding || network->policy != SUCRUNE_NETWORK_OUTBOUND || !outbound_unicast(address))
            return -EACCES;
        return source ? 0 : select_outbound(network, slot);
    }
    if (source) {
        if (physical_dns(network,address)) {
            if (!slot->dns_registered || address->family!=AF_INET) return -EACCES;
            address->address[3]=53U;address->port=53U;return 0;
        }
        return loopback(address) ? 0 : -EACCES;
    }
    if (physical_dns(network,address)) return -EACCES;
    if (binding) {
        /* Managed DNS clients and build tools request an ephemeral source.
         * Never bind their wildcard on the actual device. */
        static const unsigned char unspecified[16] = {0};
        if (slot->protocol == IPPROTO_UDP && address->port == 0U &&
            (network->policy == SUCRUNE_NETWORK_OUTBOUND || network->build_profile) &&
            address->scope_id == 0U && address->flowinfo == 0U &&
            memcmp(address->address, unspecified, sizeof(unspecified)) == 0) {
            if (address->family == AF_INET) {
                address->address[0] = 127U;
                address->address[3] = 1U;
            } else if (address->family == AF_INET6) address->address[15] = 1U;
        }
        return loopback(address) ? 0 : -EACCES;
    }
    if (address->port==0U) return -EINVAL;
    if (virtual_dns(address)) {
        if (network->policy!=SUCRUNE_NETWORK_OUTBOUND) return -EACCES;
        if (network->hooks.dns_add==NULL) return -ENETUNREACH;
        int bound=ensure_udp_loopback_source(slot,address);if (bound!=0) return bound;
        int error=register_dns(network,slot);if (error!=0) return error;
        address->address[3]=1U;address->port=network->hooks.dns_port;return 0;
    }
    if (loopback(address)) return ensure_udp_loopback_source(slot,address);
    if (network->policy!=SUCRUNE_NETWORK_OUTBOUND || slot->type!=SOCK_STREAM ||
        !outbound_unicast(address)) return -EACCES;
    return select_outbound(network, slot);
}
static int decode_route(struct sucrune_network_broker *network, struct sucrune_net_slot *slot,
        const void *bytes, size_t size, int binding, int source, struct sockaddr_storage *output, socklen_t *length) {
    struct sucrune_socket_address address;
    int error=sucrune_socket_address_decode(bytes,size,&address);
    if (error!=0) return error;
    int domain=slot->domain;
    if (address.family!=domain || size!=(domain==AF_INET ? 16U : 28U)) return -EINVAL;
    error=route_address(network,slot,&address,binding,source);
    if (error!=0) return error;
    memset(output, 0, sizeof(*output));
    if (domain == AF_INET) {
        struct sockaddr_in native = {.sin_family = AF_INET, .sin_port = htons(address.port)};
        memcpy(&native.sin_addr, address.address, 4U); memcpy(output, &native, sizeof(native)); *length = sizeof(native);
    } else {
        struct sockaddr_in6 native = {.sin6_family = AF_INET6, .sin6_port = htons(address.port)};
        memcpy(&native.sin6_addr, address.address, 16U); memcpy(output, &native, sizeof(native)); *length = sizeof(native);
    }
    return 0;
}
static int native_address(struct sucrune_network_broker *network, struct sucrune_net_slot *slot,
        const struct sucrune_request *request, struct sockaddr_storage *output, socklen_t *length) {
    int route=request->operation==SUCRUNE_NET_ROUTE;
    if ((route && (request->args[2]!=(int64_t)request->size || (request->args[1]!=0 && request->args[1]!=1))) ||
        (!route && (request->args[1]!=(int64_t)request->size || request->args[2]!=0))) return -EINVAL;
    return decode_route(network,slot,request->data,request->size,request->operation==SUCRUNE_NET_BIND,
        route && request->args[1]==1,output,length);
}

static int64_t create_echo_channel(struct sucrune_network_broker *network, int index,
        int kernel_fd, int domain, int protocol, int *send_fd) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) != 0) {
        int error = errno;
        (void)close(kernel_fd);
        return -error;
    }
    if (network->echo_packet == NULL) {
        network->echo_packet = malloc(SUCRUNE_NET_ECHO_PACKET_LIMIT);
        if (network->echo_packet == NULL) {
            (void)close(pair[0]); (void)close(pair[1]); (void)close(kernel_fd);
            return -ENOMEM;
        }
    }
    int64_t token = adopt(network, index, kernel_fd, domain, SOCK_DGRAM, protocol);
    network->slots[index].echo_peer = pair[0];
    network->echo_count++;
    *send_fd = pair[1];
    return token;
}

static int send_echo(struct sucrune_network_broker *network, struct sucrune_net_slot *slot,
        const struct sucrune_request *request, struct sucrune_response *response) {
    if (slot->echo_peer < 0) return -ENOTSOCK;
    /* Consume the matching record even when the address or flags are denied.
     * No previous payload may be reused after an unsuccessful send. */
    ssize_t bytes = recv(slot->echo_peer, network->echo_packet, SUCRUNE_NET_ECHO_PACKET_LIMIT, MSG_DONTWAIT | MSG_TRUNC);
    if (bytes < 0) return -errno;
    if ((size_t)bytes > SUCRUNE_NET_ECHO_PACKET_LIMIT) return -EMSGSIZE;
    if (request->args[2] != 0 || (request->args[1] & ~(int64_t)(MSG_DONTWAIT | MSG_NOSIGNAL))) return -EINVAL;
    struct sockaddr_storage address;
    socklen_t length = 0;
    if (request->size != 0U) {
        int error = decode_route(network, slot, request->data, request->size, 0, 0, &address, &length);
        if (error != 0) return error;
    }
    ssize_t sent = sendto(slot->fd, network->echo_packet, (size_t)bytes, MSG_DONTWAIT | MSG_NOSIGNAL,
        length ? (struct sockaddr *)&address : NULL, length);
    if (sent < 0) return -errno;
    sucrune_net_put_u32(response->data + SUCRUNE_NET_REPLY_HEADER, (uint32_t)sent);
    response->size += 4U;
    return 0;
}

static void forward_echo(struct sucrune_network_broker *network, struct sucrune_net_slot *slot) {
    struct sockaddr_storage native;
    socklen_t length = sizeof(native);
    ssize_t bytes = recvfrom(slot->fd, network->echo_packet, SUCRUNE_NET_ECHO_PACKET_LIMIT, MSG_DONTWAIT,
        (struct sockaddr *)&native, &length);
    unsigned char header[SUCRUNE_NET_ECHO_SOURCE_BYTES] = {0};
    int error = 0;
    if (bytes < 0) {
        if (errno == EAGAIN || errno == EINTR) return;
        error = errno;
    } else {
        struct sucrune_socket_address source;
        if (length != (slot->domain == AF_INET ? 16U : 28U) || native.ss_family != slot->domain ||
            sucrune_socket_address_decode(&native, length, &source) != 0) return;
        if (route_address(network, slot, &source, 0, 1) != 0) return;
        size_t encoded = 0;
        if (sucrune_socket_address_encode(&source, header, sizeof(header), &encoded) != 0) return;
    }
    if (error != 0) sucrune_net_put_u32(header + 4U, (uint32_t)error);
    struct iovec pieces[] = {{header, sizeof(header)}, {network->echo_packet, bytes > 0 ? (size_t)bytes : 0U}};
    struct msghdr message = {.msg_iov = pieces, .msg_iovlen = 2U};
    /* A full or closed receiver drops a datagram just like a full socket
     * receive queue. It never stalls sibling files, sockets or broker teardown. */
    (void)sendmsg(slot->echo_peer, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
}

int sucrune_network_wait_control(struct sucrune_network_broker *network, int control_fd) {
    if (network->echo_count == 0U) return 0;
    struct pollfd fds[1U + SUCRUNE_NET_RESOURCE_LIMIT] = {{.fd=control_fd, .events=POLLIN}};
    struct sucrune_net_slot *slots[SUCRUNE_NET_RESOURCE_LIMIT];
    nfds_t count = 1;
    for (size_t i = 0; i < SUCRUNE_NET_RESOURCE_LIMIT; i++) {
        struct sucrune_net_slot *slot = &network->slots[i];
        if (slot->fd < 0 || slot->echo_peer < 0) continue;
        slots[count - 1U] = slot;
        fds[count++] = (struct pollfd){.fd=slot->fd, .events=POLLIN};
    }
    for (;;) {
        if (poll(fds, count, -1) < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        for (nfds_t i = 1; i < count; i++)
            if (fds[i].revents) forward_echo(network, slots[i - 1U]);
        if (fds[0].revents) return 0;
    }
}
static int encode_address(const struct sockaddr_storage *storage, socklen_t length,
        struct sucrune_response *response) {
    struct sucrune_socket_address address = {0};
    if (storage->ss_family == AF_INET && length == sizeof(struct sockaddr_in)) {
        struct sockaddr_in native; memcpy(&native, storage, sizeof(native));
        address.family = AF_INET; address.port = ntohs(native.sin_port); memcpy(address.address, &native.sin_addr, 4U);
    } else if (storage->ss_family == AF_INET6 && length == sizeof(struct sockaddr_in6)) {
        struct sockaddr_in6 native; memcpy(&native, storage, sizeof(native));
        address.family = AF_INET6; address.port = ntohs(native.sin6_port);
        address.flowinfo = ntohl(native.sin6_flowinfo); address.scope_id = native.sin6_scope_id;
        memcpy(address.address, &native.sin6_addr, 16U);
    } else return -EAFNOSUPPORT;
    size_t size = 0U;
    int error = sucrune_socket_address_encode(&address, response->data + SUCRUNE_NET_REPLY_HEADER,
        SUCRUNE_IO_LIMIT - SUCRUNE_NET_REPLY_HEADER, &size);
    if (error == 0) response->size = SUCRUNE_NET_REPLY_HEADER + (uint32_t)size;
    return error;
}
static int option_allowed(const struct sucrune_net_slot *slot, int level, int option, int setting) {
    if (level == SOL_SOCKET) switch (option) {
        case SO_TYPE: case SO_ERROR: case SO_ACCEPTCONN: case SO_DOMAIN: case SO_PROTOCOL: return !setting;
        case SO_RCVBUF: case SO_SNDBUF: case SO_KEEPALIVE: case SO_REUSEADDR: case SO_REUSEPORT: case SO_OOBINLINE: return 1;
        default: return 0;
    }
    if (level == IPPROTO_TCP) return option == TCP_NODELAY || option == TCP_KEEPIDLE || option == TCP_KEEPINTVL || option == TCP_KEEPCNT;
    if (slot->type == SOCK_STREAM && ((level == IPPROTO_IP && option == IP_TOS) ||
        (level == IPPROTO_IPV6 && option == IPV6_TCLASS))) return 1;
    if (level == IPPROTO_IP) return option == IP_RECVERR;
    return level == IPPROTO_IPV6 && (option == IPV6_V6ONLY || option == IPV6_RECVERR);
}
/* PlainDatagramSocketImpl initializes these kernel flags even for unicast.
 * Destination and source routing and group membership remain independently
 * checked. Restrict the compatibility options to the build loopback socket. */
static int build_udp_option(const struct sucrune_network_broker *network,const struct sucrune_net_slot *slot,
        int level,int option,int setting,int value) {
    if (!network->build_profile || network->policy!=SUCRUNE_NETWORK_LOOPBACK ||
        slot->protocol!=IPPROTO_UDP) return 0;
    if (level==SOL_SOCKET && option==SO_BROADCAST) return !setting || value==0 || value==1;
    if (slot->domain==AF_INET && level==IPPROTO_IP && option==IP_MULTICAST_ALL) return !setting || value==0;
    return slot->domain==AF_INET6 && level==IPPROTO_IPV6 && option==IPV6_MULTICAST_HOPS && (!setting || value==1);
}
static int64_t control(struct sucrune_network_broker *network, unsigned int other,
        const struct sucrune_request *request, struct sucrune_response *response, int *send_fd) {
    uint32_t operation = request->operation;
    if (request->args[3] != SUCRUNE_NET_VERSION || request->reserved != 0U) return -EINVAL;
    if (operation == SUCRUNE_NET_EXEC_KEEP) return keep_after_exec(network,request);
    if (network->policy == SUCRUNE_NETWORK_NONE) return -EACCES;
    if (operation == SUCRUNE_NET_SOCKET || operation == SUCRUNE_NET_ECHO_SOCKET) {
        if (request->size != 0U || (request->args[0] != AF_INET && request->args[0] != AF_INET6)) return -EAFNOSUPPORT;
        int64_t type64=request->args[1]&~(int64_t)(SOCK_NONBLOCK|SOCK_CLOEXEC);
        if ((type64!=SOCK_STREAM && type64!=SOCK_DGRAM) ||
            (type64==SOCK_STREAM && (request->args[1]&SOCK_NONBLOCK)==0)) return -EOPNOTSUPP;
        int domain = (int)request->args[0], type = (int)type64;
        int protocol = type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP;
        int echo_protocol = domain == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6;
        if (operation == SUCRUNE_NET_ECHO_SOCKET) {
            if (type != SOCK_DGRAM || request->args[2] != echo_protocol) return -EPROTONOSUPPORT;
            protocol = echo_protocol;
        } else if (request->args[2] != 0 && request->args[2] != protocol) return -EPROTONOSUPPORT;
        int index = free_slot(network, other); if (index < 0) return index;
        int fd=socket(domain,type|SOCK_NONBLOCK|SOCK_CLOEXEC,protocol);
        if (fd < 0) return -errno;
        if (operation == SUCRUNE_NET_ECHO_SOCKET) return create_echo_channel(network,index,fd,domain,protocol,send_fd);
        *send_fd=fd;return adopt(network,index,fd,domain,type,protocol);
    }
    struct sucrune_net_slot *slot = lookup(network, request->args[0]);
    if (slot == NULL) return -EBADF;
    if (operation == SUCRUNE_NET_ECHO_SEND) return send_echo(network,slot,request,response);
    if (operation==SUCRUNE_NET_BIND || operation==SUCRUNE_NET_CONNECT || operation==SUCRUNE_NET_ROUTE) {
        struct sockaddr_storage address; socklen_t length = 0;
        if (operation==SUCRUNE_NET_ROUTE && slot->type!=SOCK_DGRAM) return -EOPNOTSUPP;
        int error=native_address(network,slot,request,&address,&length);
        if (error != 0) return error;
        if (operation==SUCRUNE_NET_ROUTE) return encode_address(&address,length,response);
        error = ensure_nonblocking(slot->fd); if (error != 0) return error;
        int result = operation == SUCRUNE_NET_BIND ? bind(slot->fd, (struct sockaddr *)&address, length) :
            connect(slot->fd, (struct sockaddr *)&address, length);
        if (result == 0 && operation == SUCRUNE_NET_BIND) slot->bound = 1;
        return result == 0 ? 0 : -errno;
    }
    if (operation == SUCRUNE_NET_GETOPT || operation == SUCRUNE_NET_SETOPT) {
        int setting = operation == SUCRUNE_NET_SETOPT;
        if (request->size != (setting ? 4U : 0U) || request->args[1] < 0 || request->args[1] > INT_MAX ||
            request->args[2] < 0 || request->args[2] > INT_MAX) return -EINVAL;
        int level = (int)request->args[1], option = (int)request->args[2];
        int value = setting ? (int32_t)sucrune_net_u32(request->data) : 0;
        if (!option_allowed(slot, level, option, setting) && !build_udp_option(network,slot,level,option,setting,value))
            return -ENOPROTOOPT;
        if (((level == IPPROTO_IP && option == IP_RECVERR) || (level == IPPROTO_IPV6 && option == IPV6_RECVERR)) &&
            (slot->protocol != IPPROTO_UDP || slot->domain != (level == IPPROTO_IP ? AF_INET : AF_INET6))) return -ENOPROTOOPT;
        if (setting) {
            if (slot->dns_registered && level==SOL_SOCKET && (option==SO_REUSEADDR || option==SO_REUSEPORT) && value!=0) return -EACCES;
            if (level == SOL_SOCKET && (option == SO_RCVBUF || option == SO_SNDBUF) &&
                (value < 0 || value > 16 * 1024 * 1024)) return -EINVAL;
            return setsockopt(slot->fd, level, option, &value, sizeof(value)) == 0 ? 0 : -errno;
        }
        socklen_t length = sizeof(value);
        if (getsockopt(slot->fd, level, option, &value, &length) != 0) return -errno;
        if (length != sizeof(value)) return -EIO;
        sucrune_net_put_u32(response->data + SUCRUNE_NET_REPLY_HEADER, (uint32_t)value);
        response->size += 4U; return 0;
    }
    if (request->size != 0U || request->args[2] != 0) return -EINVAL;
    switch (operation) {
        case SUCRUNE_NET_LISTEN:
            if (slot->type!=SOCK_STREAM || slot->dns_registered) return -EOPNOTSUPP;
            if (request->args[1] < 0 || request->args[1] > 128) return -EINVAL;
            /* listen() on an unbound socket would silently bind INADDR_ANY. */
            if (!slot->bound) return -EACCES;
            return listen(slot->fd, (int)request->args[1]) == 0 ? 0 : -errno;
        case SUCRUNE_NET_ACCEPT: {
            if (slot->type!=SOCK_STREAM) return -EOPNOTSUPP;
            if (request->args[1] != SOCK_NONBLOCK && request->args[1] != (SOCK_NONBLOCK | SOCK_CLOEXEC)) return -EOPNOTSUPP;
            int index = free_slot(network, other); if (index < 0) return index;
            int error = ensure_nonblocking(slot->fd); if (error != 0) return error;
            struct sockaddr_storage address; memset(&address, 0, sizeof(address)); socklen_t length = sizeof(address);
            int fd = accept4(slot->fd, (struct sockaddr *)&address, &length, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (fd < 0) return -errno;
            error = encode_address(&address, length, response);
            if (error != 0) { (void)close(fd); return error; }
            *send_fd=fd;return adopt(network,index,fd,slot->domain,SOCK_STREAM,IPPROTO_TCP);
        }
        case SUCRUNE_NET_NAME: {
            if (request->args[1] != 0 && request->args[1] != 1) return -EINVAL;
            struct sockaddr_storage address; memset(&address, 0, sizeof(address)); socklen_t length = sizeof(address);
            int result = request->args[1] == 0 ? getsockname(slot->fd, (struct sockaddr *)&address, &length) :
                getpeername(slot->fd, (struct sockaddr *)&address, &length);
            if (result!=0) return -errno;
            if (request->args[1]==1 && slot->protocol!=IPPROTO_ICMP && address.ss_family==AF_INET && length==sizeof(struct sockaddr_in)) {
                struct sockaddr_in peer;memcpy(&peer,&address,sizeof(peer));
                if (network->hooks.dns_port!=0U && peer.sin_addr.s_addr==htonl(INADDR_LOOPBACK) && ntohs(peer.sin_port)==network->hooks.dns_port) {
                    if (!slot->dns_registered) return -EACCES;
                    peer.sin_addr.s_addr=htonl(UINT32_C(0x7f000035));peer.sin_port=htons(53U);memcpy(&address,&peer,sizeof(peer));
                }
            }
            return encode_address(&address,length,response);
        }
        case SUCRUNE_NET_SHUTDOWN:
            if (request->args[1] < SHUT_RD || request->args[1] > SHUT_RDWR) return -EINVAL;
            if (slot->echo_peer >= 0) return -EOPNOTSUPP;
            return shutdown(slot->fd, (int)request->args[1]) == 0 ? 0 : -errno;
        case SUCRUNE_NET_RELEASE: {
            if (request->args[1] != 0) return -EINVAL;
            return release_slot(network,slot);
        }
        default: return -ENOSYS;
    }
}
void sucrune_network_dispatch(struct sucrune_network_broker *network,
        unsigned int other_resources, const struct sucrune_request *request,
        struct sucrune_response *response, int *send_fd) {
    memset(response, 0, sizeof(*response)); response->magic = SUCRUNE_BROKER_MAGIC;
    response->size = SUCRUNE_NET_REPLY_HEADER; sucrune_net_put_u32(response->data, SUCRUNE_NET_VERSION);
    *send_fd = -1;
    response->result = control(network, other_resources, request, response, send_fd);
    if (response->result < 0) response->size = SUCRUNE_NET_REPLY_HEADER;
    sucrune_net_put_u32(response->data + 4U, *send_fd >= 0 ? 1U : 0U);
}
#endif
