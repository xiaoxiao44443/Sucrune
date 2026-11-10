#ifndef SUCRUNE_BROKER_TRANSPORT_H
#define SUCRUNE_BROKER_TRANSPORT_H
#include "workspace_broker.h"

/* One complete packet per SOCK_SEQPACKET message. A finite timeout_ms bounds
 * the whole call using MSG_DONTWAIT and poll. With timeout_ms == -1, the
 * manager waits in recvmsg on a blocking socket. Shared FD flags are unchanged.
 * Receivers validate exact wire sizes and ancillary data and close all received
 * rights on every rejection. Requests never accept rights. OPEN_READ may
 * carry one CLOEXEC, O_RDONLY regular file; the slot also works without it.
 * A protocol error shuts down the channel, but never closes the caller's FD.
 * Successful receive_response transfers one FD only when received_fd != NULL
 * and the operation (network creation, fork session, PTY master, read-only
 * file mapping) announces it; initialize output to -1.
 * A passed PTY master must be CLOEXEC, a character device, and report the
 * claimed kernel PTY number. PTY slave responses never pass a descriptor.
 * Returned FDs are CLOEXEC, nonblocking INET/INET6 TCP or UDP sockets matching
 * the constructor's type/domain; ACCEPT admits TCP only. ECHO_SOCKET returns
 * only a connected anonymous nonblocking Unix seqpacket endpoint. No token or FD
 * is published to guest memory by this transport layer.
 */
int sucrune_broker_send_request(int fd, const struct sucrune_request *request, int timeout_ms);
int sucrune_broker_receive_request(int fd, struct sucrune_request *request, int timeout_ms);
int sucrune_broker_send_response(int fd, uint32_t operation,
    const struct sucrune_response *response, int send_fd, int timeout_ms);
int sucrune_broker_receive_response(int fd, uint32_t operation,
    struct sucrune_response *response, int *received_fd, int timeout_ms);
/* Caller serializes transactions, including existing file RPC. Any failed
 * exchange poisons the channel: do not resume another request after failure. */
int sucrune_broker_exchange(int fd, const struct sucrune_request *request,
    struct sucrune_response *response, int *received_fd, int timeout_ms);
#endif
