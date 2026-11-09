#ifndef SUCRUNE_NETWORK_PROBE_H
#define SUCRUNE_NETWORK_PROBE_H

#include <stddef.h>

enum sucrune_network_probe_mode {
    SUCRUNE_NETWORK_DIRECT = 0,
    SUCRUNE_NETWORK_CONNECTED = 1,
    SUCRUNE_NETWORK_CONNECT = 2,
    SUCRUNE_NETWORK_ACCEPT = 3
};

/* Network-order address bytes, not a sockaddr or a string. Accept only exact
 * 127.0.0.1 (4 bytes), ::1 (16 bytes), or ::ffff:127.0.0.1 (16 bytes). Android
 * dual-stack Java sockets can report that last form for an IPv4 connection.
 * All other addresses/lengths, including other 127/8 addresses, are rejected.
 * This pure helper is available with SUCRUNE_NETWORK_PROBE_CODEC_ONLY. */
int sucrune_network_probe_loopback_bytes(const unsigned char *address, size_t length);

/* Diagnostic only, not a guest syscall implementation. All sockets address
 * loopback. Modes 1/2 send PING and receive PONG; mode 3 receives PING and sends
 * PONG. A manager must run the counterpart concurrently. Mode 2 uses port.
 *
 * timeout_ms is a shared monotonic budget in [1, 3000], not a per-call timeout.
 * borrowed_fd remains caller-owned. Its shared O_NONBLOCK flag, SO_KEEPALIVE
 * and TCP_NODELAY options may be enabled; these probe effects are not restored.
 * Every descriptor created here is closed before return, including on failure.
 *
 * Returns 0 when a complete JSON capability report was produced. Individual
 * denied operations are reported with their errno, not treated as API failure.
 * Returns -EINVAL for invalid parameters, -ENOSPC for an insufficient report
 * buffer. Provide at least 8192 bytes. This probes Binder/PFD-delivered handles
 * when used with that transport; it does not itself test SCM_RIGHTS delivery.
 */
int sucrune_network_probe_run(int mode, int borrowed_fd, int loopback_port,
                             int timeout_ms, char *report, size_t capacity);

#endif
