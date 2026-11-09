#ifndef SUCRUNE_PTY_RUNTIME_H
#define SUCRUNE_PTY_RUNTIME_H
#include <stddef.h>
#include <stdint.h>

/* Serialize registry lookup, publication and last-description release with
 * the guest FD-table lock. A record owns exactly one canonical FD; dup aliases
 * in guest_fds share it. No extra open slave delays EOF at the master. */
#define SUCRUNE_PTY_ENDPOINTS 64U
#define SUCRUNE_PTY_BUFFER 36U
enum sucrune_pty_kind { SUCRUNE_PTY_NONE, SUCRUNE_PTY_MASTER, SUCRUNE_PTY_SLAVE };
struct sucrune_pty_endpoint { int fd, number; enum sucrune_pty_kind kind; };
struct sucrune_pty_table { struct sucrune_pty_endpoint entries[SUCRUNE_PTY_ENDPOINTS]; };
enum sucrune_pty_argument {
    SUCRUNE_PTY_GET, SUCRUNE_PTY_SET, SUCRUNE_PTY_SCALAR,
    SUCRUNE_PTY_OPEN_PEER, SUCRUNE_PTY_SET_GROUP
};
struct sucrune_pty_request {
    enum sucrune_pty_argument argument;
    size_t size;
    int may_wait;
};

/* Use only in the dedicated native guest runner. No manager/ART process may
 * call controlling-terminal/session operations. Open returns an owned
 * registered canonical FD or negative errno. Preflight guest FD capacity,
 * then publish as LOCAL or call release on publication failure. */
void sucrune_pty_init(struct sucrune_pty_table *table);
enum sucrune_pty_kind sucrune_pty_kind(const struct sucrune_pty_table *table, int fd);
int sucrune_pty_number(const struct sucrune_pty_table *table, int fd);
/* Restore only authenticated same-execution exec handoff descriptions.
 * Verifies kernel endpoint identity, accepts each canonical FD once and sets
 * host CLOEXEC. Success adopts fd and returns 0. Failure does not adopt fd. */
int sucrune_pty_adopt(struct sucrune_pty_table *table, int fd, enum sucrune_pty_kind kind, int number);
/* Exact absolute /dev/ptmx, /dev/tty and /dev/pts/ prefix. Malformed or
 * foreign slave paths fail closed in open; unrecognized paths use the broker. */
int sucrune_pty_path(const char *path);
int sucrune_pty_open_flags(uint64_t guest_flags, int *physical_flags);
int sucrune_pty_open(struct sucrune_pty_table *table, const char *path, uint64_t guest_flags);
int sucrune_pty_peer(struct sucrune_pty_table *table, int master, uint64_t guest_flags);
int sucrune_pty_release(struct sucrune_pty_table *table, int fd);

/* plan() rejects unknown requests and endpoint-inappropriate commands. GET
 * requires a writable guest buffer, SET/SET_GROUP a readable buffer; copy
 * exactly size bytes to/from aligned HOST storage. All host FDs passed to
 * apply must be the canonical FD or a pin of the selected registered endpoint.
 * For may_wait (TCSETSW/F) pin, unlock, call, then relock/revalidate.
 * OPEN_PEER uses peer() and normal guest FD publication. SET_GROUP requires
 * caller approval of membership in the guest's owned process group/session.
 * TIOCSCTTY supports non-stealing acquisition only by the real session leader.
 * Never apply a guest's unchecked ioctl/request, PID or memory pointer. */
int sucrune_pty_plan(enum sucrune_pty_kind kind, uint64_t command, struct sucrune_pty_request *plan);
int sucrune_pty_apply(enum sucrune_pty_kind kind, int pinned_fd, uint64_t command,
                      uint64_t scalar, void *host_buffer, size_t size, int allowed_group);
#endif
