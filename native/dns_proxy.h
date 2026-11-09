#ifndef SUCRUNE_DNS_PROXY_H
#define SUCRUNE_DNS_PROXY_H
#include <stddef.h>
#include <stdint.h>

#define SUCRUNE_DNS_QUERY_MAX 4096U
#define SUCRUNE_DNS_ANSWER_MAX 65535U
#define SUCRUNE_DNS_QUERY_LIMIT 8U
#define SUCRUNE_DNS_WORKER_LIMIT 4U
#define SUCRUNE_DNS_CLIENT_LIMIT 64U
#define SUCRUNE_DNS_TCP_LIMIT 8U
#define SUCRUNE_DNS_UDP 1
#define SUCRUNE_DNS_TCP 2

struct sucrune_dns_proxy;
struct sucrune_dns_config {
    uint64_t network_handle; /* 0 explicitly selects Android's default network. */
    unsigned int query_timeout_ms; /* 1..30000; includes queue and collection. */
};
/* All callbacks return negative POSIX errors, never -1 plus errno. submit runs
 * on a worker, returns an owned pollable SOCK_STREAM FD, and retains no query
 * pointer. collect and cancel each CONSUME that FD on every return. collect
 * must unblock when another alias of its socket is shutdown. Proxy never calls
 * cancel concurrently with collect. userdata must outlive successful join.
 * A stalled submit has no public Android hard timeout: join may time out and
 * leave the object owned; it must not be freed or counted as cleaned up. */
struct sucrune_dns_backend {
    void *userdata;
    int (*submit)(void *, uint64_t network, const unsigned char *, size_t);
    int (*collect)(void *, int fd, int *rcode, unsigned char *, size_t);
    void (*cancel)(void *, int fd);
};
struct sucrune_dns_stats {
    uint64_t admitted, answered, malformed, unregistered, capacity_rejected;
    uint64_t backend_errors, cancelled, timed_out;
    unsigned int pending, workers_started, workers_exited;
    int listeners_closed, joined;
};
/* start returns a manager-owned UDP+TCP loopback proxy. It does not authorize
 * guest network access, change resolv.conf, or install any runtime mapping.
 * NULL backend selects Android API29 raw resolver (ENOTSUP on other hosts).
 * Calls below are thread-safe except join/destroy: exactly one joining owner,
 * and no calls may race destroy. No guest memory or signal-handler use. */
int sucrune_dns_proxy_start(const struct sucrune_dns_config *,
    const struct sucrune_dns_backend *, struct sucrune_dns_proxy **);
int sucrune_dns_proxy_endpoint(struct sucrune_dns_proxy *, uint16_t *port);
/* canonical_fd is borrowed; register AFTER local bind/autobind, BEFORE guest
 * data I/O. Its type must match transport. INADDR_ANY local bind is accepted
 * because only 127.0.0.1 sources reach this proxy. token is manager metadata,
 * never a guest FD. Do not reuse a retired token during this proxy's lifetime.
 * A live token and transport/port pair must each be unique. */
int sucrune_dns_proxy_allow_client(struct sucrune_dns_proxy *, int transport,
    int canonical_fd, uint64_t token);
int sucrune_dns_proxy_remove_client(struct sucrune_dns_proxy *, uint64_t token);
void sucrune_dns_proxy_request_stop(struct sucrune_dns_proxy *);
/* Caller requests stop first. ETIMEDOUT keeps every object/thread owned; retry
 * join later. Success means real pthread joins, not merely stop requested. */
int sucrune_dns_proxy_join(struct sucrune_dns_proxy *, int timeout_ms,
    struct sucrune_dns_stats *);
int sucrune_dns_proxy_destroy(struct sucrune_dns_proxy *);

/* Bounded codec used by the proxy and portable host regression tests. Supports
 * one standard query question, DNS name compression, and EDNS UDP size. No
 * address is synthesized. question includes canonical name, type and class. */
struct sucrune_dns_question {
    uint16_t id, udp_limit;
    size_t wire_end, key_length;
    unsigned char key[259];
};
int sucrune_dns_parse_query(const void *, size_t, struct sucrune_dns_question *);
int sucrune_dns_validate_answer(const void *, size_t,
    const struct sucrune_dns_question *);
/* For a response received from Android's raw resolver, return the validated
 * byte extent through the last counted RR, or -errno. Anything following that
 * extent is not sent to the guest. validate_answer still requires exact EOF. */
int sucrune_dns_system_answer_length(const void *, size_t,
    const struct sucrune_dns_question *);
#endif
