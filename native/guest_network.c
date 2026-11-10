#include "guest_network.h"
#include "broker_transport.h"
#include "guest_sockets.h"
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

/* Android supervision enforces the original execution deadline independently.
 * Each control exchange also has a finite bound; it never restarts that deadline. */
#define NETWORK_CONTROL_TIMEOUT_MS 5000

void sucrune_guest_network_init(struct sucrune_guest_network *network, int broker) {
    memset(network, 0, sizeof(*network));
    network->broker = broker;
    for (size_t i = 0; i < SUCRUNE_NET_RESOURCE_LIMIT; i++) network->entries[i].fd = -1;
}
static struct sucrune_guest_network_entry *entry(struct sucrune_guest_network *network, int fd) {
    if (fd < 0) return NULL;
    for (size_t i = 0; i < SUCRUNE_NET_RESOURCE_LIMIT; i++)
        if (network->entries[i].fd == fd) return &network->entries[i];
    return NULL;
}
int sucrune_guest_network_contains(const struct sucrune_guest_network *network, int fd) {
    if (fd < 0) return 0;
    for (size_t i = 0; i < SUCRUNE_NET_RESOURCE_LIMIT; i++)
        if (network->entries[i].fd == fd) return 1;
    return 0;
}
int sucrune_guest_network_type(const struct sucrune_guest_network *network, int fd) {
    if (network!=NULL && fd>=0) for (size_t i=0U;i<SUCRUNE_NET_RESOURCE_LIMIT;i++)
        if (network->entries[i].fd==fd) return network->entries[i].type;
    return -EBADF;
}
int sucrune_guest_network_udp_state(const struct sucrune_guest_network *network,int fd) {
    if (network!=NULL && fd>=0) for (size_t i=0U;i<SUCRUNE_NET_RESOURCE_LIMIT;i++)
        if (network->entries[i].fd==fd && network->entries[i].type==SOCK_DGRAM) return network->entries[i].udp_state;
    return -ENOTSOCK;
}
static int invalid_reply(struct sucrune_guest_network *network, int received) {
    if (received >= 0) (void)close(received);
    (void)shutdown(network->broker, SHUT_RDWR);
    return -EPROTO;
}
static int exchange(struct sucrune_guest_network *network, struct sucrune_request *request,
                    struct sucrune_response *response, int *received) {
    request->magic = SUCRUNE_BROKER_MAGIC;
    request->args[3] = SUCRUNE_NET_VERSION;
    int error = sucrune_broker_exchange(network->broker, request, response, received, NETWORK_CONTROL_TIMEOUT_MS);
    if (error != 0) return error;
    if (response->size < SUCRUNE_NET_REPLY_HEADER ||
        sucrune_net_u32(response->data) != SUCRUNE_NET_VERSION) return invalid_reply(network, *received);
    if (response->result < 0) {
        if (response->result < -4095 || response->size != SUCRUNE_NET_REPLY_HEADER || *received >= 0)
            return invalid_reply(network, *received);
        return (int)response->result;
    }
    return 0;
}
static int admit(struct sucrune_guest_network *network, int fd, int type, int64_t token, int echo_domain) {
    for (size_t i = 0; i < SUCRUNE_NET_RESOURCE_LIMIT; i++) if (network->entries[i].fd < 0) {
        network->entries[i] = (struct sucrune_guest_network_entry){.fd = fd, .type = type, .token = token, .echo_domain = echo_domain};
        network->count++;
        if (network->count > network->peak) network->peak = network->count;
        return fd;
    }
    return invalid_reply(network, fd); /* Capacity was reserved by the caller. */
}
uint64_t sucrune_guest_network_token(const struct sucrune_guest_network *network, int fd) {
    if (network!=NULL && fd>=0) for (size_t i=0;i<SUCRUNE_NET_RESOURCE_LIMIT;i++)
        if (network->entries[i].fd==fd) return (uint64_t)network->entries[i].token;
    return 0;
}
int sucrune_guest_network_restore_tcp(struct sucrune_guest_network *network, int fd, uint64_t token) {
    if (network==NULL || fd<0 || !sucrune_net_token_valid((int64_t)token)) return -EINVAL;
    size_t free_index=SUCRUNE_NET_RESOURCE_LIMIT;
    for (size_t i=0;i<SUCRUNE_NET_RESOURCE_LIMIT;i++) {
        const struct sucrune_guest_network_entry *e=&network->entries[i];
        if (e->fd<0) { if (free_index==SUCRUNE_NET_RESOURCE_LIMIT) free_index=i; continue; }
        if (e->fd==fd || e->token==(int64_t)token) return -EINVAL;
    }
    if (free_index==SUCRUNE_NET_RESOURCE_LIMIT) return -EMFILE;
    int type=0, flags=fcntl(fd,F_GETFL); socklen_t length=sizeof(type);
    if (flags<0 || getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&length)<0) return -errno;
    if (length!=sizeof(type) || type!=SOCK_STREAM || (flags&O_NONBLOCK)==0) return -EPROTO;
    network->entries[free_index]=(struct sucrune_guest_network_entry){.fd=fd,.type=type,.token=(int64_t)token};
    network->count++;
    if (network->count>network->peak) network->peak=network->count;
    return 0;
}
static void put_u64(unsigned char *row,uint64_t value) {
    sucrune_net_put_u32(row,(uint32_t)value);
    sucrune_net_put_u32(row+4U,(uint32_t)(value>>32U));
}
int sucrune_guest_network_commit_exec(struct sucrune_guest_network *network) {
    struct sucrune_request request={.operation=SUCRUNE_NET_EXEC_KEEP};
    for (size_t i=0;i<SUCRUNE_NET_RESOURCE_LIMIT;i++) {
        const struct sucrune_guest_network_entry *e=&network->entries[i];
        if (e->fd<0) continue;
        if (e->type!=SOCK_STREAM) return -EOPNOTSUPP;
        struct stat st;
        if (fstat(e->fd,&st)!=0) return -errno;
        if (!S_ISSOCK(st.st_mode)) return -ENOTSOCK;
        unsigned char *row=request.data+request.size;
        put_u64(row,(uint64_t)e->token); put_u64(row+8U,(uint64_t)st.st_dev); put_u64(row+16U,(uint64_t)st.st_ino);
        request.size+=SUCRUNE_NET_KEEP_BYTES; request.args[0]++;
    }
    struct sucrune_response response;
    int received=-1;
    int error=exchange(network,&request,&response,&received);
    if (error!=0) return error;
    if (received>=0 || response.result!=0 || response.size!=SUCRUNE_NET_REPLY_HEADER)
        return invalid_reply(network,received);
    return 0;
}
int sucrune_guest_network_socket(struct sucrune_guest_network *network, int domain, int type, int protocol) {
    if (network->count >= SUCRUNE_NET_RESOURCE_LIMIT) return -EMFILE;
    int base_type = type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
    int echo = base_type == SOCK_DGRAM && ((domain == AF_INET && protocol == IPPROTO_ICMP) ||
        (domain == AF_INET6 && protocol == IPPROTO_ICMPV6));
    struct sucrune_request request = {.operation = echo ? SUCRUNE_NET_ECHO_SOCKET : SUCRUNE_NET_SOCKET,
        .args = {domain, type, protocol, 0}};
    struct sucrune_response response;
    int received = -1;
    int error = exchange(network, &request, &response, &received);
    if (error != 0) return error;
    if (received < 0 || !sucrune_net_token_valid(response.result) ||
        response.size != SUCRUNE_NET_REPLY_HEADER) return invalid_reply(network, received);
    return admit(network, received, base_type, response.result, echo ? domain : 0);
}
int sucrune_guest_network_echo_domain(const struct sucrune_guest_network *network, int fd) {
    if (network && fd >= 0) for (size_t i = 0; i < SUCRUNE_NET_RESOURCE_LIMIT; i++)
        if (network->entries[i].fd == fd) return network->entries[i].echo_domain;
    return 0;
}

static ssize_t send_echo(struct sucrune_guest_network *network, struct sucrune_guest_network_entry *socket,
                         struct msghdr *message, int flags) {
    struct sucrune_request request = {.operation = SUCRUNE_NET_ECHO_SEND,
        .args = {socket->token, flags, 0, 0}};
    if (message->msg_name) {
        size_t length = socket->echo_domain == AF_INET ? 16U : 28U;
        struct sucrune_socket_address address;
        if (message->msg_namelen != length) return -EINVAL;
        if (sucrune_socket_address_decode(message->msg_name, length, &address) != 0 ||
            address.family != socket->echo_domain) return -EAFNOSUPPORT;
        request.size = (uint32_t)length;
        memcpy(request.data, message->msg_name, length);
    }
    size_t bytes = 0;
    size_t count = (size_t)message->msg_iovlen;
    if (count > 1024U) return -EMSGSIZE;
    for (size_t i = 0; i < count; i++) {
        if (message->msg_iov[i].iov_len > SUCRUNE_NET_ECHO_PACKET_LIMIT - bytes) return -EMSGSIZE;
        bytes += message->msg_iov[i].iov_len;
    }
    /* An echo datagram has an eight-byte ICMP header. Do not queue an empty
     * seqpacket (the peer also uses EOF for transport teardown). */
    if (bytes < 8U) return -EINVAL;
    struct msghdr outgoing = {.msg_iov = message->msg_iov, .msg_iovlen = message->msg_iovlen};
    ssize_t queued = sendmsg(socket->fd, &outgoing, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (queued < 0) return -errno;
    if ((size_t)queued != bytes) return invalid_reply(network, -1);
    struct sucrune_response response;
    int received = -1;
    int error = exchange(network, &request, &response, &received);
    if (error) return error;
    if (received >= 0 || response.result != 0 || response.size != SUCRUNE_NET_REPLY_HEADER + 4U ||
        sucrune_net_u32(response.data + SUCRUNE_NET_REPLY_HEADER) != bytes) return invalid_reply(network, received);
    socket->udp_state |= SUCRUNE_UDP_BOUND;
    return queued;
}

ssize_t sucrune_guest_network_echo_message(struct sucrune_guest_network *network, int fd,
        int receiving, struct msghdr *message, int flags) {
    struct sucrune_guest_network_entry *socket = entry(network, fd);
    if (!socket || !socket->echo_domain) return -ENOTSOCK;
    if (!message) return -EINVAL;
    if (!receiving) return send_echo(network, socket, message, flags);
    if (message->msg_iovlen != 1 || !message->msg_name ||
        message->msg_namelen < SUCRUNE_NET_ECHO_SOURCE_BYTES) return -EINVAL;

    unsigned char source[SUCRUNE_NET_ECHO_SOURCE_BYTES];
    struct iovec parts[] = {{.iov_base = source, .iov_len = sizeof(source)}, message->msg_iov[0]};
    struct msghdr incoming = {.msg_iov = parts, .msg_iovlen = 2};
    ssize_t size = recvmsg(fd, &incoming, flags | MSG_DONTWAIT);
    if (size < 0) return -errno;
    if (!size) return -ECONNRESET;
    if ((size_t)size < sizeof(source)) return invalid_reply(network, -1);
    if (source[0] == 0U && source[1] == 0U) {
        uint32_t error = sucrune_net_u32(source + 4);
        for (size_t i = 0; i < sizeof(source); i++)
            if ((i < 4U || i >= 8U) && source[i]) return invalid_reply(network, -1);
        if ((size_t)size != sizeof(source) || (incoming.msg_flags & MSG_TRUNC) ||
            !error || error > 4095U) return invalid_reply(network, -1);
        return -(int)error;
    }
    if (source[0] != socket->echo_domain || source[1] != 0U) return invalid_reply(network, -1);
    size_t length = socket->echo_domain == AF_INET ? 16U : 28U;
    for (size_t i = length; i < sizeof(source); i++)
        if (source[i] != 0U) return invalid_reply(network, -1);
    memcpy(message->msg_name, source, length);
    message->msg_namelen = (socklen_t)length;
    message->msg_flags = incoming.msg_flags & MSG_TRUNC;
    return size - (ssize_t)sizeof(source);
}

int sucrune_guest_network_accept(struct sucrune_guest_network *network, int fd, int flags,
    void *address, size_t capacity, size_t *length) {
    struct sucrune_guest_network_entry *found = entry(network, fd);
    if (found == NULL) return -ENOTSOCK;
    if (length == NULL || (address == NULL && capacity != 0U)) return -EFAULT;
    if (network->count >= SUCRUNE_NET_RESOURCE_LIMIT) return -EMFILE;
    struct sucrune_request request = {.operation = SUCRUNE_NET_ACCEPT, .args = {found->token, flags, 0, 0}};
    struct sucrune_response response;
    int received = -1;
    int error = exchange(network, &request, &response, &received);
    if (error != 0) return error;
    size_t bytes = response.size - SUCRUNE_NET_REPLY_HEADER;
    struct sucrune_socket_address normalized;
    if (received < 0 || !sucrune_net_token_valid(response.result) ||
        sucrune_socket_address_decode(response.data + SUCRUNE_NET_REPLY_HEADER, bytes, &normalized) != 0 ||
        (normalized.family != 2U && normalized.family != 10U)) return invalid_reply(network, received);
    int adopted = admit(network, received, SOCK_STREAM, response.result, 0);
    if (adopted < 0) return adopted;
    size_t copied = capacity < bytes ? capacity : bytes;
    if (copied != 0U) memcpy(address, response.data + SUCRUNE_NET_REPLY_HEADER, copied);
    *length = bytes;
    return adopted;
}
int sucrune_guest_network_control(struct sucrune_guest_network *network, int fd,
    uint32_t operation, int64_t argument, int64_t option, const void *input, size_t input_length,
    void *output, size_t capacity, size_t *output_length) {
    struct sucrune_guest_network_entry *found = entry(network, fd);
    if (found == NULL) return -ENOTSOCK;
    if (input_length > SUCRUNE_SOCKET_ADDRESS_LIMIT || (input_length != 0U && input == NULL) ||
        (capacity != 0U && output == NULL) || output_length == NULL) return -EINVAL;
    struct sucrune_request request = {.operation = operation, .args = {found->token, argument, option, 0},
        .size = (uint32_t)input_length};
    if (input_length != 0U) memcpy(request.data, input, input_length);
    struct sucrune_response response;
    int received = -1;
    int error = exchange(network, &request, &response, &received);
    if (error != 0) return error;
    size_t bytes = response.size - SUCRUNE_NET_REPLY_HEADER;
    if (received >= 0 || response.result != 0 || bytes > SUCRUNE_SOCKET_ADDRESS_LIMIT)
        return invalid_reply(network, received);
    if (operation == SUCRUNE_NET_NAME || operation == SUCRUNE_NET_ROUTE) {
        struct sucrune_socket_address normalized;
        if (sucrune_socket_address_decode(response.data + SUCRUNE_NET_REPLY_HEADER, bytes, &normalized) != 0 ||
            (normalized.family != 2U && normalized.family != 10U)) return invalid_reply(network, -1);
    } else if (bytes != (operation == SUCRUNE_NET_GETOPT ? 4U : 0U)) return invalid_reply(network, -1);
    size_t copied = capacity < bytes ? capacity : bytes;
    if (copied != 0U) memcpy(output, response.data + SUCRUNE_NET_REPLY_HEADER, copied);
    *output_length = operation == SUCRUNE_NET_GETOPT ? copied : bytes;
    return 0;
}
int sucrune_guest_network_route(struct sucrune_guest_network *network, int fd, int source,
    const void *address, size_t length, void *output, size_t capacity, size_t *output_length) {
    if ((source!=0 && source!=1) || (length!=16U && length!=28U)) return -EINVAL;
    int result=sucrune_guest_network_control(network,fd,SUCRUNE_NET_ROUTE,source,(int64_t)length,
        address,length,output,capacity,output_length);
    if (result==0 && source==0) entry(network,fd)->udp_state|=SUCRUNE_UDP_BOUND;
    return result;
}
int sucrune_guest_network_address(struct sucrune_guest_network *network, int fd,
    int connect_operation, const void *address, size_t length) {
    if (length > SUCRUNE_SOCKET_ADDRESS_LIMIT) return -EINVAL;
    size_t unused = 0;
    int result=sucrune_guest_network_control(network,fd,connect_operation ? SUCRUNE_NET_CONNECT : SUCRUNE_NET_BIND,
        (int64_t)length,0,address,length,NULL,0,&unused);
    if (result==0) {struct sucrune_guest_network_entry *found=entry(network,fd);
        if (found->type==SOCK_DGRAM) found->udp_state|=SUCRUNE_UDP_BOUND|(connect_operation ? SUCRUNE_UDP_CONNECTED : 0);}
    return result;
}
int sucrune_guest_network_release(struct sucrune_guest_network *network, int fd) {
    struct sucrune_guest_network_entry *found = entry(network, fd);
    if (found == NULL) return -ENOTSOCK;
    size_t unused = 0;
    int error = sucrune_guest_network_control(network, fd, SUCRUNE_NET_RELEASE, 0, 0, NULL, 0, NULL, 0, &unused);
    found->fd = -1; found->token = 0; network->count--;
    int closed = close(fd);
    return error != 0 ? error : (closed == 0 ? 0 : -errno);
}
