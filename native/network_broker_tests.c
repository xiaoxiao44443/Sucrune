#include "network_broker.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(value) do { if (!(value)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #value); exit(1); } } while (0)
static unsigned int passed;
static void wire_tokens(void) {
    unsigned char bytes[4];
    sucrune_net_put_u32(bytes, UINT32_C(0xa173f609));
    CHECK(bytes[0] == 9U && bytes[1] == 246U && bytes[2] == 115U && bytes[3] == 161U);
    CHECK(sucrune_net_u32(bytes) == UINT32_C(0xa173f609));
    for (uint64_t slot = 0U; slot < 64U; slot++) {
        CHECK(!sucrune_net_token_valid((int64_t)(SUCRUNE_NET_TOKEN_PREFIX | slot)));
        CHECK(sucrune_net_token_valid((int64_t)(SUCRUNE_NET_TOKEN_PREFIX | UINT64_C(64) | slot)));
        CHECK(sucrune_net_token_valid((int64_t)(SUCRUNE_NET_TOKEN_PREFIX | (SUCRUNE_NET_GENERATION_MAX << 6U) | slot)));
    }
    for (unsigned int bit = 48U; bit < 64U; bit++)
        CHECK(!sucrune_net_token_valid((int64_t)((SUCRUNE_NET_TOKEN_PREFIX | UINT64_C(64)) ^ (UINT64_C(1) << bit))));
    CHECK(!sucrune_net_token_valid(-1) && !sucrune_net_token_valid(3) && !sucrune_net_token_valid(66));
    CHECK(!sucrune_net_operation(198U) && !sucrune_net_operation(SUCRUNE_BROKER_EXEC_COMMIT));
    CHECK(!sucrune_net_operation(SUCRUNE_NET_SOCKET - 1U) && !sucrune_net_operation(SUCRUNE_NET_EXEC_KEEP + 1U));
    for (uint32_t operation = SUCRUNE_NET_SOCKET; operation <= SUCRUNE_NET_EXEC_KEEP; operation++) CHECK(sucrune_net_operation(operation));
    passed++;
}
#if !defined(SUCRUNE_NETWORK_WIRE_ONLY)
#include "broker_transport.h"
#include "guest_network.h"
#include "guest_fds.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
struct client { int fd, done; };
struct remote_socket { int fd; int64_t token; };
static struct sucrune_request packet(uint32_t operation) {
    struct sucrune_request request = {.magic = SUCRUNE_BROKER_MAGIC, .operation = operation};
    if (sucrune_net_operation(operation)) request.args[3] = SUCRUNE_NET_VERSION;
    return request;
}
static struct sucrune_response exchange(struct client client, const struct sucrune_request *request, int *fd) {
    struct sucrune_response response;
    CHECK(sucrune_broker_exchange(client.fd, request, &response, fd, 2000) == 0);
    return response;
}
static struct client start(const char *workspace, int policy) {
    struct client client;
    client.fd = sucrune_workspace_broker_with_network(workspace, &client.done, policy);
    CHECK(client.fd >= 0 && client.done >= 0); return client;
}
static void wait_ready(int fd, short events) {
    struct pollfd item = {.fd = fd, .events = events};
    int result; do { result = poll(&item, 1U, 2000); } while (result < 0 && errno == EINTR);
    CHECK(result == 1 && (item.revents & (events | POLLHUP)) != 0);
}
static void finish(struct client client) {
    CHECK(close(client.fd) == 0); wait_ready(client.done, POLLIN);
    char byte; CHECK(read(client.done, &byte, 1U) == 0); CHECK(close(client.done) == 0);
}
static struct remote_socket create_socket(struct client client) {
    struct sucrune_request request = packet(SUCRUNE_NET_SOCKET);
    request.args[0] = AF_INET; request.args[1] = SOCK_STREAM | SOCK_NONBLOCK;
    struct remote_socket socket = {.fd = -1};
    struct sucrune_response response = exchange(client, &request, &socket.fd);
    CHECK(sucrune_net_token_valid(response.result) && socket.fd >= 0);
    socket.token = response.result;
    CHECK((fcntl(socket.fd, F_GETFD) & FD_CLOEXEC) != 0 && (fcntl(socket.fd, F_GETFL) & O_NONBLOCK) != 0);
    return socket;
}
static int64_t simple(struct client client, uint32_t operation, int64_t token, int64_t argument) {
    struct sucrune_request request = packet(operation); request.args[0] = token; request.args[1] = argument;
    struct sucrune_response response = exchange(client, &request, NULL); return response.result;
}
static void release(struct client client, struct remote_socket socket) {
    CHECK(simple(client, SUCRUNE_NET_RELEASE, socket.token, 0) == 0); CHECK(close(socket.fd) == 0);
}
static struct sucrune_request address_request(uint32_t operation, int64_t token, uint16_t port) {
    struct sucrune_request request = packet(operation); request.args[0] = token; request.args[1] = 16; request.size = 16U;
    request.data[0] = AF_INET; request.data[2] = (unsigned char)(port >> 8U); request.data[3] = (unsigned char)port;
    request.data[4] = 127U; request.data[7] = 1U; return request;
}
static uint16_t bound_port(struct client client, struct remote_socket socket) {
    struct sucrune_request request = packet(SUCRUNE_NET_NAME); request.args[0] = socket.token;
    struct sucrune_response response = exchange(client, &request, NULL);
    CHECK(response.result == 0 && response.size == SUCRUNE_NET_REPLY_HEADER + 16U);
    return (uint16_t)(((uint16_t)response.data[10] << 8U) | response.data[11]);
}
static void policy_and_tokens(const char *workspace) {
    int done = 77;
    CHECK(sucrune_workspace_broker_with_network(workspace, &done, 999) == -EINVAL && done == -1);
    struct client disabled; disabled.fd = sucrune_workspace_broker(workspace, &disabled.done); CHECK(disabled.fd >= 0);
    struct sucrune_request request = packet(SUCRUNE_NET_SOCKET); request.args[0] = AF_INET; request.args[1] = SOCK_STREAM | SOCK_NONBLOCK;
    int right = -1; struct sucrune_response response = exchange(disabled, &request, &right);
    CHECK(response.result == -EACCES && right == -1); finish(disabled);
    struct client client = start(workspace, SUCRUNE_NETWORK_LOOPBACK);
    struct remote_socket first = create_socket(client); release(client, first);
    struct remote_socket second = create_socket(client); CHECK(second.token != first.token);
    CHECK(simple(client, SUCRUNE_NET_RELEASE, first.token, 0) == -EBADF);
    CHECK(simple(client, SUCRUNE_NET_NAME, 3, 0) == -EBADF);
    CHECK(simple(client, SUCRUNE_NET_LISTEN, second.token, 1) == -EACCES);
    request = address_request(SUCRUNE_NET_BIND, second.token, 0U); memset(request.data + 4U, 0, 4U);
    CHECK(exchange(client, &request, NULL).result == -EACCES);
    request = address_request(SUCRUNE_NET_CONNECT, second.token, 443U); request.data[4] = 192U; request.data[5] = 0U; request.data[6] = 2U;
    CHECK(exchange(client, &request, NULL).result == -EACCES);
    request = packet(SUCRUNE_NET_NAME); request.args[0] = second.token; request.args[3] = 2;
    CHECK(exchange(client, &request, NULL).result == -EINVAL);
    request = packet(57U); request.args[0] = second.token; CHECK(exchange(client, &request, NULL).result == -EBADF);
    release(client, second); finish(client); passed++;
}
static void tcp_roundtrip(const char *workspace) {
    struct client client = start(workspace, SUCRUNE_NETWORK_LOOPBACK);
    struct remote_socket server = create_socket(client);
    struct sucrune_request request = address_request(SUCRUNE_NET_BIND, server.token, 0U);
    CHECK(exchange(client, &request, NULL).result == 0); uint16_t port = bound_port(client, server); CHECK(port != 0U);
    CHECK(simple(client, SUCRUNE_NET_LISTEN, server.token, 16) == 0);
    request = packet(SUCRUNE_NET_ACCEPT); request.args[0] = server.token; request.args[1] = SOCK_NONBLOCK;
    int right = -1; CHECK(exchange(client, &request, &right).result == -EAGAIN && right == -1);
    struct remote_socket outgoing = create_socket(client);
    request = address_request(SUCRUNE_NET_CONNECT, outgoing.token, port);
    int64_t result = exchange(client, &request, NULL).result; CHECK(result == 0 || result == -EINPROGRESS);
    wait_ready(outgoing.fd, POLLOUT); wait_ready(server.fd, POLLIN);
    request = packet(SUCRUNE_NET_GETOPT); request.args[0] = outgoing.token; request.args[1] = SOL_SOCKET; request.args[2] = SO_ERROR;
    struct sucrune_response response = exchange(client, &request, NULL);
    CHECK(response.result == 0 && response.size == 12U && sucrune_net_u32(response.data + 8U) == 0U);
    request = packet(SUCRUNE_NET_ACCEPT); request.args[0] = server.token; request.args[1] = SOCK_NONBLOCK | SOCK_CLOEXEC;
    struct remote_socket incoming = {.fd = -1}; response = exchange(client, &request, &incoming.fd);
    CHECK(sucrune_net_token_valid(response.result) && incoming.fd >= 0 && response.size == 24U); incoming.token = response.result;
    int alias = fcntl(outgoing.fd, F_DUPFD_CLOEXEC, 3); CHECK(alias >= 0);
    CHECK(send(alias, "PING", 4U, MSG_NOSIGNAL) == 4); wait_ready(incoming.fd, POLLIN);
    char bytes[8]; CHECK(recv(incoming.fd, bytes, sizeof(bytes), 0) == 4 && memcmp(bytes, "PING", 4U) == 0);
    CHECK(simple(client, SUCRUNE_NET_SHUTDOWN, outgoing.token, SHUT_WR) == 0); wait_ready(incoming.fd, POLLIN);
    CHECK(recv(incoming.fd, bytes, sizeof(bytes), 0) == 0);
    CHECK(send(incoming.fd, "PONG", 4U, MSG_NOSIGNAL) == 4); wait_ready(alias, POLLIN);
    CHECK(recv(alias, bytes, sizeof(bytes), 0) == 4 && memcmp(bytes, "PONG", 4U) == 0);
    CHECK(close(alias) == 0); release(client, outgoing); release(client, incoming); release(client, server);
    finish(client); passed++;
}
static struct client child_session(struct client parent,int expected) {
    struct sucrune_request fork=packet(SUCRUNE_BROKER_FORK_SESSION);
    struct client child={.fd=-1,.done=-1};
    CHECK(exchange(parent,&fork,&child.fd).result==expected);
    CHECK((child.fd>=0)==(expected==0));
    return child;
}
static void connected_fork_exec(const char *workspace) {
    struct client parent=start(workspace,SUCRUNE_NETWORK_LOOPBACK);
    struct remote_socket listener=create_socket(parent);
    (void)child_session(parent,-EOPNOTSUPP);
    struct sucrune_request request=address_request(SUCRUNE_NET_BIND,listener.token,0);
    CHECK(exchange(parent,&request,NULL).result==0);
    (void)child_session(parent,-EOPNOTSUPP);
    CHECK(simple(parent,SUCRUNE_NET_LISTEN,listener.token,1)==0);
    struct remote_socket outgoing=create_socket(parent);
    request=address_request(SUCRUNE_NET_CONNECT,outgoing.token,bound_port(parent,listener));
    int64_t result=exchange(parent,&request,NULL).result;
    CHECK(result==0 || result==-EINPROGRESS);
    wait_ready(listener.fd,POLLIN);
    request=packet(SUCRUNE_NET_ACCEPT);request.args[0]=listener.token;request.args[1]=SOCK_NONBLOCK;
    struct remote_socket incoming={.fd=-1};
    incoming.token=exchange(parent,&request,&incoming.fd).result;
    CHECK(incoming.fd>=0 && sucrune_net_token_valid(incoming.token));
    release(parent,listener);
    struct client child=child_session(parent,0);
    struct sucrune_guest_network inherited;
    sucrune_guest_network_init(&inherited,child.fd);
    int duplicate=fcntl(outgoing.fd,F_DUPFD_CLOEXEC,3);
    CHECK(duplicate>=0);
    CHECK(sucrune_guest_network_restore_tcp(&inherited,duplicate,(uint64_t)incoming.token)==0);
    /* A valid token from this session describing a *different* real socket
     * must fail without releasing any slot. Token numbers alone are not proof. */
    CHECK(sucrune_guest_network_commit_exec(&inherited)==-EPROTO);
    CHECK(simple(child,SUCRUNE_NET_NAME,incoming.token,1)==0 && simple(child,SUCRUNE_NET_NAME,outgoing.token,1)==0);
    sucrune_guest_network_init(&inherited,child.fd);
    CHECK(sucrune_guest_network_restore_tcp(&inherited,duplicate,(uint64_t)outgoing.token)==0);
    CHECK(sucrune_guest_network_restore_tcp(&inherited,duplicate,(uint64_t)outgoing.token)==-EINVAL);
    CHECK(sucrune_guest_network_token(&inherited,duplicate)==(uint64_t)outgoing.token);
    CHECK(simple(parent,SUCRUNE_NET_EXEC_KEEP,0,0)==-EPERM);
    CHECK(sucrune_guest_network_commit_exec(&inherited)==0);
    CHECK(simple(child,SUCRUNE_NET_NAME,incoming.token,1)==-EBADF);
    CHECK(simple(child,SUCRUNE_NET_NAME,outgoing.token,1)==0 && simple(parent,SUCRUNE_NET_NAME,incoming.token,1)==0);
    /* The child sends and receives on the retained kernel TCP connection.
     * Only its manager slot is released when its last guest alias closes. */
    char data[4];
    CHECK(send(duplicate,"K",1U,MSG_NOSIGNAL)==1);wait_ready(incoming.fd,POLLIN);
    CHECK(read(incoming.fd,data,sizeof(data))==1 && data[0]=='K');
    CHECK(send(incoming.fd,"A",1U,MSG_NOSIGNAL)==1);wait_ready(duplicate,POLLIN);
    CHECK(read(duplicate,data,sizeof(data))==1 && data[0]=='A');
    CHECK(sucrune_guest_network_release(&inherited,duplicate)==0 && inherited.count==0U);
    CHECK(simple(child,SUCRUNE_NET_NAME,outgoing.token,1)==-EBADF);
    CHECK(simple(parent,SUCRUNE_NET_NAME,outgoing.token,1)==0);
    CHECK(send(outgoing.fd,"P",1U,MSG_NOSIGNAL)==1);wait_ready(incoming.fd,POLLIN);
    CHECK(read(incoming.fd,data,sizeof(data))==1 && data[0]=='P');
    CHECK(close(child.fd)==0);
    /* Roll back a partial copy when a later slot is a UDP resource. */
    struct sucrune_guest_network parent_net;
    sucrune_guest_network_init(&parent_net,parent.fd);
    int udp=sucrune_guest_network_socket(&parent_net,AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    CHECK(udp>=0);
    (void)child_session(parent,-EOPNOTSUPP);
    CHECK(sucrune_guest_network_release(&parent_net,udp)==0);
    release(parent,outgoing); release(parent,incoming); finish(parent);
    passed++;
}
static void listener_fork_exec(const char *workspace, int domain) {
    struct client parent = start(workspace, SUCRUNE_NETWORK_LOOPBACK);
    struct sucrune_guest_network parent_net;
    sucrune_guest_network_init(&parent_net, parent.fd);
    int listener = sucrune_guest_network_socket(&parent_net, domain, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    CHECK(listener >= 0);
    uint64_t token = sucrune_guest_network_token(&parent_net, listener);
    unsigned char loopback[28] = {0};
    loopback[0] = (unsigned char)domain;
    size_t size = domain == AF_INET ? 16U : 28U;
    if (domain == AF_INET) loopback[4] = 127U;
    loopback[domain == AF_INET ? 7 : 23] = 1U;
    CHECK(sucrune_guest_network_address(&parent_net, listener, 0, loopback, size) == 0);
    CHECK(simple(parent, SUCRUNE_NET_LISTEN, (int64_t)token, 4) == 0);
    struct sockaddr_storage address;
    socklen_t length = sizeof(address);
    CHECK(getsockname(listener, (struct sockaddr *)&address, &length) == 0 && length == size);

    /* A shell normally execs with the server listener marked close-on-exec.
     * An empty retained set releases only that child's manager reference. */
    struct client shell = child_session(parent, 0);
    CHECK(simple(shell, SUCRUNE_NET_EXEC_KEEP, 0, 0) == 0);
    CHECK(simple(shell, SUCRUNE_NET_NAME, (int64_t)token, 0) == -EBADF);
    CHECK(close(shell.fd) == 0);

    /* With a surviving alias, the new image keeps the same listening socket
     * after the parent closes its copy and can accept a real connection. */
    struct client child = child_session(parent, 0);
    struct sucrune_guest_network child_net;
    sucrune_guest_network_init(&child_net, child.fd);
    int alias = fcntl(listener, F_DUPFD_CLOEXEC, 3);
    CHECK(alias >= 0 && (fcntl(alias, F_GETFD) & FD_CLOEXEC) && (fcntl(alias, F_GETFL) & O_NONBLOCK));
    CHECK(sucrune_guest_network_restore_tcp(&child_net, alias, token) == 0);
    CHECK(sucrune_guest_network_commit_exec(&child_net) == 0);
    CHECK(sucrune_guest_network_release(&parent_net, listener) == 0);
    int peer = socket(domain, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    CHECK(peer >= 0 && connect(peer, (struct sockaddr *)&address, length) == 0);
    wait_ready(alias, POLLIN);
    size_t peer_size = 0;
    int accepted = sucrune_guest_network_accept(&child_net, alias, SOCK_NONBLOCK | SOCK_CLOEXEC, NULL, 0, &peer_size);
    CHECK(accepted >= 0 && peer_size == size);
    CHECK(send(peer, "L", 1, MSG_NOSIGNAL) == 1 && close(peer) == 0);
    char byte;
    wait_ready(accepted, POLLIN);
    CHECK(read(accepted, &byte, 1) == 1 && byte == 'L');
    wait_ready(accepted, POLLIN);
    CHECK(read(accepted, &byte, 1) == 0);
    CHECK(sucrune_guest_network_release(&child_net, accepted) == 0);
    int reuse = socket(domain, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    CHECK(reuse >= 0 && bind(reuse, (struct sockaddr *)&address, length) == -1 && errno == EADDRINUSE);
    CHECK(sucrune_guest_network_release(&child_net, alias) == 0);
    CHECK(simple(child, SUCRUNE_NET_NAME, (int64_t)token, 0) == -EBADF);
    CHECK(bind(reuse, (struct sockaddr *)&address, length) == 0 && close(reuse) == 0);
    CHECK(close(child.fd) == 0);
    finish(parent);
    passed++;
}
static void resource_quota_and_cleanup(const char *workspace) {
    struct client client = start(workspace, SUCRUNE_NETWORK_LOOPBACK);
    struct remote_socket sockets[64]; for (size_t i = 0U; i < 64U; i++) sockets[i] = create_socket(client);
    struct sucrune_request request = packet(SUCRUNE_NET_SOCKET); request.args[0] = AF_INET; request.args[1] = SOCK_STREAM | SOCK_NONBLOCK;
    int right = -1; CHECK(exchange(client, &request, &right).result == -EMFILE && right == -1);
    request = packet(56U); request.args[0] = AT_FDCWD; request.args[1] = O_WRONLY | O_CREAT | O_TRUNC;
    memcpy(request.data, "/quota-created", sizeof("/quota-created")); request.size = sizeof("/quota-created");
    CHECK(exchange(client, &request, NULL).result == -EMFILE);
    char path[1024]; int length = snprintf(path, sizeof(path), "%s/quota-created", workspace);
    CHECK(length > 0 && (size_t)length < sizeof(path)); CHECK(access(path, F_OK) == -1 && errno == ENOENT);
    release(client, sockets[0]);
    CHECK(exchange(client, &request, NULL).result >= 3);
    request = packet(SUCRUNE_NET_SOCKET); request.args[0] = AF_INET; request.args[1] = SOCK_STREAM | SOCK_NONBLOCK;
    CHECK(exchange(client, &request, &right).result == -EMFILE && right == -1);
    for (size_t i = 1U; i < 64U; i++) CHECK(close(sockets[i].fd) == 0);
    /* All 63 remote canonical sockets and one file remain for EOF cleanup. */
    finish(client); CHECK(unlink(path) == 0); passed++;
}
static int fail_alias(void *context, enum sucrune_fd_kind kind, int fd, int *alias) {
    (void)context; CHECK(kind == SUCRUNE_FD_LOCAL && fd >= 0); *alias = -1; return -EMFILE;
}
static int unexpected_close(void *context, enum sucrune_fd_kind kind, int fd) {
    (void)context; (void)kind; (void)fd; CHECK(0); return -EIO;
}
static void client_adapter_rollback(const char *workspace) {
    struct client client = start(workspace, SUCRUNE_NETWORK_LOOPBACK);
    struct sucrune_guest_network network; sucrune_guest_network_init(&network, client.fd);
    int server = sucrune_guest_network_socket(&network, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    CHECK(server >= 0 && network.count == 1U && sucrune_guest_network_contains(&network, server));
    struct sucrune_request address = address_request(SUCRUNE_NET_BIND, 0, 0U);
    CHECK(sucrune_guest_network_address(&network, server, 0, address.data, address.size) == 0);
    unsigned char bytes[128]; size_t length = 0U;
    CHECK(sucrune_guest_network_control(&network, server, SUCRUNE_NET_NAME, 0, 0, NULL, 0U,
        bytes, sizeof(bytes), &length) == 0 && length == 16U);
    address.data[2] = bytes[2]; address.data[3] = bytes[3];
    CHECK(sucrune_guest_network_control(&network, server, SUCRUNE_NET_LISTEN, 1, 0, NULL, 0U, NULL, 0U, &length) == 0);
    int outgoing = sucrune_guest_network_socket(&network, AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
    CHECK(outgoing >= 0);
    int connected = sucrune_guest_network_address(&network, outgoing, 1, address.data, address.size);
    CHECK(connected == 0 || connected == -EINPROGRESS); wait_ready(outgoing, POLLOUT); wait_ready(server, POLLIN);
    memset(bytes, 0xa6, sizeof(bytes)); length = 77U;
    CHECK(sucrune_guest_network_control(&network, outgoing, SUCRUNE_NET_GETOPT, SOL_SOCKET, SO_TYPE,
        NULL, 0U, bytes, 1U, &length) == 0 && length == 1U && bytes[0] == SOCK_STREAM && bytes[1] == 0xa6U);
    int incoming = sucrune_guest_network_accept(&network, server, SOCK_NONBLOCK, NULL, 0U, &length);
    CHECK(incoming >= 0 && length == 16U && network.count == 3U);
    int64_t token = 0;
    for (size_t i = 0U; i < SUCRUNE_NET_RESOURCE_LIMIT; i++) if (network.entries[i].fd == incoming) token = network.entries[i].token;
    CHECK(sucrune_net_token_valid(token));
    struct sucrune_fd_table table;
    sucrune_fds_init(&table, -1, -1, -1, O_RDONLY, O_WRONLY, NULL, NULL);
    CHECK(sucrune_fds_close(&table, 0U) == 0 && sucrune_fds_close(&table, 1U) == 0 && sucrune_fds_close(&table, 2U) == 0);
    CHECK(sucrune_fds_enable_aliases(&table, fail_alias, unexpected_close, NULL) == 0);
    CHECK(sucrune_fds_add(&table, SUCRUNE_FD_LOCAL, incoming, O_RDWR | O_NONBLOCK, 0U) == -EMFILE);
    CHECK(table.count == 0U && table.resource_count == 0U);
    /* Real failed guest-alias publication: caller rolls back both authorities. */
    CHECK(sucrune_guest_network_release(&network, incoming) == 0 && network.count == 2U);
    CHECK(fcntl(incoming, F_GETFD) == -1 && errno == EBADF);
    CHECK(simple(client, SUCRUNE_NET_RELEASE, token, 0) == -EBADF);
    wait_ready(outgoing, POLLIN); CHECK(recv(outgoing, bytes, sizeof(bytes), 0) == 0);
    CHECK(sucrune_guest_network_release(&network, incoming) == -ENOTSOCK);
    CHECK(sucrune_guest_network_release(&network, outgoing) == 0);
    CHECK(sucrune_guest_network_release(&network, server) == 0 && network.count == 0U);
    CHECK(sucrune_fds_destroy(&table) == 0); finish(client); passed++;
}
static unsigned int fd_count(void) {
    DIR *directory = opendir("/proc/self/fd"); CHECK(directory != NULL); unsigned int count = 0U;
    struct dirent *entry; while ((entry = readdir(directory)) != NULL)
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) count++;
    CHECK(closedir(directory) == 0); return count;
}

static void udp_adapter_roundtrip(const char *workspace) {
    struct client client = start(workspace, SUCRUNE_NETWORK_LOOPBACK);
    struct sucrune_guest_network network;
    sucrune_guest_network_init(&network, client.fd);
    int sender = sucrune_guest_network_socket(&network, AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    int receiver = sucrune_guest_network_socket(&network, AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    CHECK(sender >= 0 && receiver >= 0 && sender != receiver && network.count == 2U);
    /* glibc refuses to open a DNS socket unless ICMP error reporting can
     * actually be enabled. Verify the underlying shared kernel description. */
    unsigned char one[4]={1,0,0,0}; size_t written=0U;
    CHECK(sucrune_guest_network_control(&network,sender,SUCRUNE_NET_SETOPT,IPPROTO_IP,IP_RECVERR,one,sizeof(one),NULL,0U,&written)==0);
    int icmp=0; socklen_t icmp_size=sizeof(icmp);
    CHECK(getsockopt(sender,IPPROTO_IP,IP_RECVERR,&icmp,&icmp_size)==0 && icmp!=0);
    int plain=sucrune_guest_network_socket(&network,AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    CHECK(plain>=0 && sucrune_guest_network_udp_state(&network,plain)==0 &&
        (fcntl(plain,F_GETFL)&O_NONBLOCK)!=0 && (fcntl(plain,F_GETFD)&FD_CLOEXEC)!=0);
    CHECK(sucrune_guest_network_release(&network,plain)==0);
    CHECK(sucrune_guest_network_socket(&network,AF_INET,SOCK_STREAM,IPPROTO_TCP)==-EOPNOTSUPP);
    CHECK(sucrune_guest_network_type(&network, sender) == SOCK_DGRAM);
    CHECK(sucrune_guest_network_udp_state(&network,sender)==0 && sucrune_guest_network_udp_state(&network,receiver)==0);
    struct sucrune_request local = address_request(SUCRUNE_NET_BIND, 0, 0U);
    CHECK(sucrune_guest_network_address(&network, receiver, 0, local.data, local.size) == 0);
    CHECK(sucrune_guest_network_udp_state(&network,receiver)==SUCRUNE_UDP_BOUND);
    unsigned char receiver_name[16], sender_name[16], source[16];
    size_t length = 0U;
    CHECK(sucrune_guest_network_control(&network, receiver, SUCRUNE_NET_NAME, 0, 0, NULL, 0U,
        receiver_name, sizeof(receiver_name), &length) == 0 && length == sizeof(receiver_name));
    struct sockaddr_in destination;
    CHECK(sucrune_guest_network_route(&network, sender, 0, receiver_name, sizeof(receiver_name),
        &destination, sizeof(destination), &length) == 0 && length == sizeof(destination));
    CHECK(destination.sin_family == AF_INET && destination.sin_port != 0U &&
        destination.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    CHECK(sucrune_guest_network_udp_state(&network,sender)==SUCRUNE_UDP_BOUND);
    CHECK(sendto(sender, "ABCDEFGH", 8U, MSG_NOSIGNAL, (struct sockaddr *)&destination, sizeof(destination)) == 8);
    wait_ready(receiver, POLLIN);
    struct sockaddr_in actual_sender;
    socklen_t address_length = sizeof(actual_sender);
    unsigned char bytes[3] = {0, 0, 0xa5U};
    CHECK(recvfrom(receiver, bytes, 2U, MSG_TRUNC, (struct sockaddr *)&actual_sender, &address_length) == 8);
    CHECK(address_length == sizeof(actual_sender) && memcmp(bytes, "AB", 2U) == 0 && bytes[2] == 0xa5U);
    CHECK(sucrune_guest_network_route(&network, receiver, 1, &actual_sender, (size_t)address_length,
        source, sizeof(source), &length) == 0 && length == sizeof(source));
    /* Source was explicitly bound to loopback before returning a private
     * destination. A wildcard-bound UDP socket must never be exposed here. */
    CHECK(sucrune_guest_network_control(&network, sender, SUCRUNE_NET_NAME, 0, 0, NULL, 0U,
        sender_name, sizeof(sender_name), &length) == 0 && length == sizeof(sender_name));
    CHECK(source[0] == AF_INET && source[1] == 0U && source[4] == 127U && source[7] == 1U &&
        memcmp(source,sender_name,sizeof(source))==0 && actual_sender.sin_port != 0U);
    CHECK(sucrune_guest_network_route(&network, receiver, 0, source, sizeof(source), &destination,
        sizeof(destination), &length) == 0 && length == sizeof(destination));
    CHECK(sendto(receiver, "", 0U, MSG_NOSIGNAL, (struct sockaddr *)&destination, sizeof(destination)) == 0);
    CHECK(sendto(receiver, "Q", 1U, MSG_NOSIGNAL, (struct sockaddr *)&destination, sizeof(destination)) == 1);
    wait_ready(sender, POLLIN);
    struct sockaddr_in actual_receiver;
    address_length = sizeof(actual_receiver);
    bytes[0] = 0xa5U;
    CHECK(recvfrom(sender, bytes, sizeof(bytes), 0, (struct sockaddr *)&actual_receiver, &address_length) == 0);
    CHECK(bytes[0] == 0xa5U && address_length == sizeof(actual_receiver));
    CHECK(sucrune_guest_network_route(&network, sender, 1, &actual_receiver, (size_t)address_length,
        source, sizeof(source), &length) == 0 && length == sizeof(source) &&
        memcmp(source, receiver_name, length) == 0);
    wait_ready(sender, POLLIN);
    CHECK(recv(sender, bytes, sizeof(bytes), 0) == 1 && bytes[0] == 'Q');
    CHECK(sucrune_guest_network_address(&network,sender,1,receiver_name,sizeof(receiver_name))==0);
    CHECK(sucrune_guest_network_udp_state(&network,sender)==(SUCRUNE_UDP_BOUND|SUCRUNE_UDP_CONNECTED));
    int injected=sucrune_guest_network_socket(&network,AF_INET,SOCK_DGRAM|SOCK_NONBLOCK,0);CHECK(injected>=0);
    struct sockaddr_in wildcard={.sin_family=AF_INET,.sin_port=0,.sin_addr={.s_addr=htonl(INADDR_ANY)}};
    CHECK(bind(injected,(struct sockaddr *)&wildcard,sizeof(wildcard))==0);
    CHECK(sucrune_guest_network_route(&network,injected,0,receiver_name,sizeof(receiver_name),&destination,sizeof(destination),&length)==-EACCES);
    CHECK(sucrune_guest_network_udp_state(&network,injected)==0 && sucrune_guest_network_release(&network,injected)==0);
    CHECK(sucrune_guest_network_release(&network, sender) == 0);
    CHECK(sucrune_guest_network_release(&network, receiver) == 0 && network.count == 0U);
    finish(client);
    passed++;
}

struct route_hooks {
    int registered, removed, selections, fd;
    uint64_t token;
    uint16_t source_port;
};

static int reject_selected_network(void *context, int fd) {
    struct route_hooks *hooks = context;
    CHECK(fcntl(fd, F_GETFD) >= 0);
    hooks->selections++;
    return -ENETUNREACH; /* Stop before a kernel connect to a non-loopback address. */
}

static int add_dns_client(void *context, int type, int fd, uint64_t token) {
    struct route_hooks *hooks = context;
    CHECK(type == SOCK_DGRAM && hooks->token == 0U && sucrune_net_token_valid((int64_t)token));
    struct sockaddr_in local;
    socklen_t length = sizeof(local);
    CHECK(getsockname(fd, (struct sockaddr *)&local, &length) == 0 && length == sizeof(local));
    CHECK(local.sin_family == AF_INET && local.sin_addr.s_addr == htonl(INADDR_LOOPBACK) && local.sin_port != 0U);
    hooks->registered++;
    hooks->fd = fd;
    hooks->token = token;
    hooks->source_port = local.sin_port;
    return 0;
}

static void remove_dns_client(void *context, uint64_t token) {
    struct route_hooks *hooks = context;
    CHECK(token == hooks->token && fcntl(hooks->fd, F_GETFD) >= 0);
    hooks->token = 0U;
    hooks->removed++;
}

static struct sucrune_response dispatch(struct sucrune_network_broker *network,
        const struct sucrune_request *request, int *fd) {
    int received = -1;
    struct sucrune_response response;
    sucrune_network_dispatch(network, 0U, request, &response, &received);
    if (fd != NULL) *fd = received;
    else CHECK(received == -1);
    return response;
}

static struct remote_socket manager_socket(struct sucrune_network_broker *network, int type) {
    struct sucrune_request request = packet(SUCRUNE_NET_SOCKET);
    request.args[0] = AF_INET;
    request.args[1] = type | SOCK_NONBLOCK;
    struct remote_socket result;
    struct sucrune_response response = dispatch(network, &request, &result.fd);
    CHECK(result.fd >= 0 && sucrune_net_token_valid(response.result));
    result.token = response.result;
    return result;
}

static struct sucrune_request route_request(int64_t token, int source, uint16_t port, unsigned char last_octet) {
    struct sucrune_request request = address_request(SUCRUNE_NET_ROUTE, token, port);
    request.args[1] = source;
    request.args[2] = request.size;
    request.data[7] = last_octet;
    return request;
}
static int64_t set_int_option(struct sucrune_network_broker *network,int64_t token,int level,int option,uint32_t value) {
    struct sucrune_request set=packet(SUCRUNE_NET_SETOPT);
    set.args[0]=token;set.args[1]=level;set.args[2]=option;set.size=4;
    sucrune_net_put_u32(set.data,value);
    return dispatch(network,&set,NULL).result;
}

/* Node's HTTP client sets the traffic class on TCP sockets when posting audio.
 * Compare both sides of the broker with the actual kernel socket. */
static void tcp_traffic_class(int domain) {
    struct sucrune_network_broker network;
    CHECK(sucrune_network_init(&network, SUCRUNE_NETWORK_LOOPBACK) == 0);
    struct sucrune_request create = packet(SUCRUNE_NET_SOCKET);
    create.args[0] = domain;
    create.args[1] = SOCK_STREAM | SOCK_NONBLOCK;
    int fd = -1;
    struct sucrune_response reply = dispatch(&network, &create, &fd);
    CHECK(fd >= 0 && sucrune_net_token_valid(reply.result));
    int64_t token = reply.result;
    int level = domain == AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
    int option = domain == AF_INET ? IP_TOS : IPV6_TCLASS;
    CHECK(set_int_option(&network, token, level, option, 0x28) == 0);
    int value = 0;
    socklen_t length = sizeof(value);
    CHECK(getsockopt(fd, level, option, &value, &length) == 0 && value == 0x28);
    struct sucrune_request get = packet(SUCRUNE_NET_GETOPT);
    get.args[0] = token;
    get.args[1] = level;
    get.args[2] = option;
    reply = dispatch(&network, &get, NULL);
    CHECK(reply.result == 0 && reply.size == SUCRUNE_NET_REPLY_HEADER + 4U &&
          sucrune_net_u32(reply.data + SUCRUNE_NET_REPLY_HEADER) == 0x28U);
    CHECK(set_int_option(&network, token, level, domain == AF_INET ? IP_TTL : IPV6_UNICAST_HOPS, 1) == -ENOPROTOOPT);
    create.args[1] = SOCK_DGRAM;
    reply = dispatch(&network, &create, &fd);
    CHECK(fd >= 0 && sucrune_net_token_valid(reply.result));
    CHECK(set_int_option(&network, reply.result, level, option, 0x28) == -ENOPROTOOPT);
    sucrune_network_destroy(&network);
    passed++;
}
static void build_udp_ephemeral_listener(int domain) {
    struct sucrune_network_broker network;
    CHECK(sucrune_network_init(&network,SUCRUNE_NETWORK_LOOPBACK)==0);
    network.total_resource_limit=SUCRUNE_FILE_RESOURCES;
    struct sucrune_request socket_request=packet(SUCRUNE_NET_SOCKET);
    socket_request.args[0]=domain; socket_request.args[1]=SOCK_DGRAM;
    int fd=-1;
    struct sucrune_response socket_reply=dispatch(&network,&socket_request,&fd);
    CHECK(fd>=0 && sucrune_net_token_valid(socket_reply.result));
    struct sucrune_request bind_request=packet(SUCRUNE_NET_BIND);
    bind_request.args[0]=socket_reply.result; bind_request.data[0]=(unsigned char)domain;
    bind_request.size=domain==AF_INET ? 16U : 28U; bind_request.args[1]=bind_request.size;
    CHECK(dispatch(&network,&bind_request,NULL).result==-EACCES);
    CHECK(set_int_option(&network,socket_reply.result,SOL_SOCKET,SO_BROADCAST,1)==-ENOPROTOOPT);
    network.build_profile=1;
    CHECK(set_int_option(&network,socket_reply.result,SOL_SOCKET,SO_BROADCAST,1)==0);
    int actual_option=0;socklen_t option_size=sizeof(actual_option);
    CHECK(getsockopt(fd,SOL_SOCKET,SO_BROADCAST,&actual_option,&option_size)==0 && actual_option==1);
    int level=domain==AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
    int option=domain==AF_INET ? IP_MULTICAST_ALL : IPV6_MULTICAST_HOPS;
    uint32_t value=domain==AF_INET ? 0U : 1U;
    CHECK(set_int_option(&network,socket_reply.result,level,option,value)==0);
    option_size=sizeof(actual_option);
    CHECK(getsockopt(fd,level,option,&actual_option,&option_size)==0 && actual_option==(int)value);
    CHECK(set_int_option(&network,socket_reply.result,level,option,value+1U)==-ENOPROTOOPT);
    CHECK(set_int_option(&network,socket_reply.result,level,domain==AF_INET ? IP_ADD_MEMBERSHIP : IPV6_JOIN_GROUP,1)==-ENOPROTOOPT);
    struct sucrune_request route=bind_request;
    route.operation=SUCRUNE_NET_ROUTE;route.args[1]=0;route.args[2]=route.size;route.data[3]=17U;
    if(domain==AF_INET) {
        memset(route.data+4,255,4); /* IPv4 limited broadcast */
        CHECK(dispatch(&network,&route,NULL).result==-EACCES);
        route.data[4]=224U; /* IPv4 multicast */
    } else {route.data[8]=255U;route.data[9]=2U;route.data[23]=1U;} /* IPv6 all-nodes multicast */
    CHECK(dispatch(&network,&route,NULL).result==-EACCES);
    route.operation=SUCRUNE_NET_CONNECT;route.args[1]=route.size;route.args[2]=0;
    CHECK(dispatch(&network,&route,NULL).result==-EACCES);
    struct sucrune_network_broker child;
    CHECK(sucrune_network_init(&child,SUCRUNE_NETWORK_LOOPBACK)==0);
    child.build_profile=1;
    CHECK(sucrune_network_fork_connected(&child,&network)==-EOPNOTSUPP && child.count==0U);
    bind_request.data[3]=17U;
    CHECK(dispatch(&network,&bind_request,NULL).result==-EACCES); /* fixed wildcard port */
    bind_request.data[3]=0U;
    size_t host_offset=domain==AF_INET ? 4U : 8U;
    bind_request.data[host_offset]=32U;
    CHECK(dispatch(&network,&bind_request,NULL).result==-EACCES); /* external bind */
    bind_request.data[host_offset]=0U;
    CHECK(dispatch(&network,&bind_request,NULL).result==0);
    network.build_profile=0;
    CHECK(sucrune_network_fork_connected(&child,&network)==-EOPNOTSUPP && child.count==0U);
    network.build_profile=1;
    CHECK(sucrune_network_fork_connected(&child,&network)==0 && child.count==1U);
    struct sucrune_request keep=packet(SUCRUNE_NET_EXEC_KEEP);
    keep.args[0]=1;keep.size=SUCRUNE_NET_KEEP_BYTES;
    sucrune_net_put_u32(keep.data,(uint32_t)socket_reply.result);
    sucrune_net_put_u32(keep.data+4U,(uint32_t)((uint64_t)socket_reply.result>>32U));
    CHECK(dispatch(&child,&keep,NULL).result==-EBADF && child.count==1U);
    keep.args[0]=0;keep.size=0;
    CHECK(dispatch(&child,&keep,NULL).result==0 && child.count==0U && network.count==1U);
    sucrune_network_destroy(&child);
    struct sockaddr_storage actual; socklen_t length=sizeof(actual);
    CHECK(getsockname(fd,(struct sockaddr *)&actual,&length)==0);
    CHECK(actual.ss_family==domain);
    if (domain==AF_INET) {
        const struct sockaddr_in *local=(const struct sockaddr_in *)&actual;
        CHECK(local->sin_port && local->sin_addr.s_addr==htonl(INADDR_LOOPBACK));
    } else {
        const struct sockaddr_in6 *local=(const struct sockaddr_in6 *)&actual;
        CHECK(local->sin6_port && IN6_IS_ADDR_LOOPBACK(&local->sin6_addr));
    }
    int peer=socket(domain,SOCK_DGRAM|SOCK_CLOEXEC,0);
    CHECK(peer>=0 && sendto(peer,"lock",4,0,(struct sockaddr *)&actual,length)==4);
    wait_ready(fd,POLLIN);
    struct sockaddr_storage origin; socklen_t origin_length=sizeof(origin); char data[4];
    CHECK(recvfrom(fd,data,sizeof(data),0,(struct sockaddr *)&origin,&origin_length)==4 && !memcmp(data,"lock",4));
    CHECK(sendto(fd,"ack",3,0,(struct sockaddr *)&origin,origin_length)==3);
    wait_ready(peer,POLLIN); CHECK(recv(peer,data,sizeof(data),0)==3 && !memcmp(data,"ack",3));
    CHECK(close(peer)==0);
    sucrune_network_destroy(&network);
    passed++;
}

static void outbound_policy_without_external_traffic(void) {
    struct sucrune_network_broker network;
    CHECK(sucrune_network_init(&network, SUCRUNE_NETWORK_OUTBOUND) == 0);
    struct route_hooks seen = {0};
    struct sucrune_network_hooks hooks = {.context = &seen, .select_socket = reject_selected_network};
    CHECK(sucrune_network_set_hooks(&network, &hooks) == 0);
    struct remote_socket tcp = manager_socket(&network, SOCK_STREAM);
    struct remote_socket udp = manager_socket(&network, SOCK_DGRAM);
    struct sucrune_request request = address_request(SUCRUNE_NET_CONNECT, tcp.token, 443U);
    static const unsigned char external[] = {192, 0, 2, 19};
    memcpy(request.data + 4U, external, sizeof(external));
    CHECK(dispatch(&network, &request, NULL).result == -ENETUNREACH && seen.selections == 1);
    request.operation = SUCRUNE_NET_BIND;
    CHECK(dispatch(&network, &request, NULL).result == -EACCES);
    request.operation = SUCRUNE_NET_CONNECT;
    request.args[0] = udp.token;
    CHECK(dispatch(&network, &request, NULL).result == -EACCES);
    request.args[0] = tcp.token;
    request.data[4] = 224U;
    CHECK(dispatch(&network, &request, NULL).result == -EACCES && seen.selections == 1);
    request = packet(SUCRUNE_NET_RELEASE);
    request.args[0] = udp.token;
    CHECK(dispatch(&network, &request, NULL).result == 0);
    request = address_request(SUCRUNE_NET_BIND, tcp.token, 0);
    CHECK(dispatch(&network, &request, NULL).result == 0);
    request = packet(SUCRUNE_NET_LISTEN);
    request.args[0] = tcp.token;
    request.args[1] = 1;
    CHECK(dispatch(&network, &request, NULL).result == 0);
    struct sucrune_network_broker child;
    CHECK(sucrune_network_init(&child, SUCRUNE_NETWORK_LOOPBACK) == 0);
    CHECK(sucrune_network_fork_connected(&child, &network) == -EINVAL && child.count == 0U);
    CHECK(sucrune_network_init(&child, SUCRUNE_NETWORK_OUTBOUND) == 0);
    CHECK(sucrune_network_fork_connected(&child, &network) == 0 && child.count == 1U);
    request = packet(SUCRUNE_NET_GETOPT);
    request.args[0] = tcp.token;
    request.args[1] = SOL_SOCKET;
    request.args[2] = SO_ACCEPTCONN;
    struct sucrune_response listening = dispatch(&child, &request, NULL);
    CHECK(listening.result == 0 && sucrune_net_u32(listening.data + SUCRUNE_NET_REPLY_HEADER) == 1U);
    sucrune_network_destroy(&child);
    sucrune_network_destroy(&network);
    passed++;
}

static void managed_dns_route_and_generation(void) {
    int echo = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_UDP);
    CHECK(echo >= 0);
    struct sockaddr_in endpoint = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(echo, (struct sockaddr *)&endpoint, sizeof(endpoint)) == 0);
    socklen_t address_size = sizeof(endpoint);
    CHECK(getsockname(echo, (struct sockaddr *)&endpoint, &address_size) == 0 && address_size == sizeof(endpoint));
    uint16_t echo_port = ntohs(endpoint.sin_port);
    CHECK(echo_port != 0U);
    struct route_hooks seen = {0};
    struct sucrune_network_hooks hooks = {.context = &seen, .select_socket = reject_selected_network,
        .dns_add = add_dns_client, .dns_remove = remove_dns_client, .dns_port = echo_port};
    struct sucrune_network_broker network;
    CHECK(sucrune_network_init(&network, SUCRUNE_NETWORK_OUTBOUND) == 0);
    CHECK(sucrune_network_set_hooks(&network, &hooks) == 0);
    struct remote_socket udp = manager_socket(&network, SOCK_DGRAM);
    struct sucrune_request physical_source = route_request(udp.token, 1, echo_port, 1U);
    CHECK(dispatch(&network, &physical_source, NULL).result == -EACCES);
    struct sucrune_request physical_dest = route_request(udp.token, 0, echo_port, 1U);
    CHECK(dispatch(&network, &physical_dest, NULL).result == -EACCES);
    struct sucrune_request virtual_dest = route_request(udp.token, 0, 53U, 53U);
    struct sucrune_response routed = dispatch(&network, &virtual_dest, NULL);
    CHECK(routed.result == 0 && routed.size == SUCRUNE_NET_REPLY_HEADER + sizeof(endpoint));
    struct sockaddr_in actual;
    memcpy(&actual, routed.data + SUCRUNE_NET_REPLY_HEADER, sizeof(actual));
    CHECK(actual.sin_addr.s_addr == endpoint.sin_addr.s_addr && actual.sin_port == endpoint.sin_port &&
        actual.sin_family == AF_INET && seen.registered == 1 && seen.token == (uint64_t)udp.token);
    CHECK(sendto(udp.fd, "DNS", 3U, MSG_NOSIGNAL, (struct sockaddr *)&actual, sizeof(actual)) == 3);
    wait_ready(echo, POLLIN);
    unsigned char bytes[4];
    struct sockaddr_in client_source;
    address_size = sizeof(client_source);
    CHECK(recvfrom(echo, bytes, sizeof(bytes), 0, (struct sockaddr *)&client_source, &address_size) == 3);
    CHECK(memcmp(bytes, "DNS", 3U) == 0 && address_size == sizeof(client_source) && client_source.sin_port == seen.source_port);
    CHECK(sendto(echo, "REPL", 4U, MSG_NOSIGNAL, (struct sockaddr *)&client_source, address_size) == 4);
    wait_ready(udp.fd, POLLIN);
    struct sockaddr_in reply_source;
    address_size = sizeof(reply_source);
    CHECK(recvfrom(udp.fd, bytes, sizeof(bytes), 0, (struct sockaddr *)&reply_source, &address_size) == 4);
    CHECK(memcmp(bytes, "REPL", 4U) == 0 && address_size == sizeof(reply_source));
    memcpy(physical_source.data, &reply_source, sizeof(reply_source));
    routed = dispatch(&network, &physical_source, NULL);
    CHECK(routed.result == 0 && routed.size == SUCRUNE_NET_REPLY_HEADER + 16U &&
        memcmp(routed.data + SUCRUNE_NET_REPLY_HEADER, virtual_dest.data, 16U) == 0);
    struct sucrune_request connect_dns = address_request(SUCRUNE_NET_CONNECT, udp.token, 53U);
    connect_dns.data[7] = 53U;
    CHECK(dispatch(&network, &connect_dns, NULL).result == 0 && seen.registered == 1);
    struct sucrune_request name = packet(SUCRUNE_NET_NAME);
    name.args[0] = udp.token;
    name.args[1] = 1;
    routed = dispatch(&network, &name, NULL);
    CHECK(routed.result == 0 && routed.size == SUCRUNE_NET_REPLY_HEADER + 16U &&
        memcmp(routed.data + SUCRUNE_NET_REPLY_HEADER, virtual_dest.data, 16U) == 0);
    CHECK(dispatch(&network, &physical_dest, NULL).result == -EACCES);
    struct sucrune_request drop = packet(SUCRUNE_NET_RELEASE);
    drop.args[0] = udp.token;
    CHECK(dispatch(&network, &drop, NULL).result == 0 && seen.removed == 1);
    CHECK(fcntl(udp.fd, F_GETFD) == -1 && errno == EBADF);
    struct remote_socket replacement = manager_socket(&network, SOCK_DGRAM);
    CHECK(replacement.token != udp.token && dispatch(&network, &virtual_dest, NULL).result == -EBADF);
    physical_source.args[0] = replacement.token;
    CHECK(dispatch(&network, &physical_source, NULL).result == -EACCES);
    virtual_dest.args[0] = replacement.token;
    CHECK(dispatch(&network, &virtual_dest, NULL).result == 0 && seen.registered == 2);
    sucrune_network_destroy(&network);
    CHECK(seen.removed == 2 && seen.token == 0U && seen.selections == 0);
    CHECK(fcntl(replacement.fd, F_GETFD) == -1 && errno == EBADF);
    CHECK(close(echo) == 0);
    passed++;
}
#endif
int main(void) {
    wire_tokens();
#if !defined(SUCRUNE_NETWORK_WIRE_ONLY)
    char workspace[] = "./sucrune-network-tests-XXXXXX"; CHECK(mkdtemp(workspace) != NULL);
    char *absolute = realpath(workspace, NULL); CHECK(absolute != NULL); unsigned int before = fd_count();
    policy_and_tokens(absolute); tcp_roundtrip(absolute); resource_quota_and_cleanup(absolute); client_adapter_rollback(absolute);
    udp_adapter_roundtrip(absolute); outbound_policy_without_external_traffic(); managed_dns_route_and_generation();
    tcp_traffic_class(AF_INET); tcp_traffic_class(AF_INET6);
    build_udp_ephemeral_listener(AF_INET); build_udp_ephemeral_listener(AF_INET6);
    connected_fork_exec(absolute);
    listener_fork_exec(absolute, AF_INET);
    listener_fork_exec(absolute, AF_INET6);
    CHECK(fd_count() == before); CHECK(rmdir(absolute) == 0); free(absolute);
#endif
    printf("Network broker: %u/%u groups passed; no Android isolated-runner or Internet capability claim.\n", passed, passed);
    return 0;
}
