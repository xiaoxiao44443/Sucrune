#ifndef SUCRUNE_PTY_BROKER_H
#define SUCRUNE_PTY_BROKER_H
#include "pty_runtime.h"
#include "workspace_broker.h"
#include <sys/stat.h>
/* Only MASTER passes a right. reply.result is its actual kernel PTY number.
 * SLAVE returns an opaque session-local handle, never a device FD. */
#define SUCRUNE_PTY_MASTER_OPEN 0x53552001U
#define SUCRUNE_PTY_SLAVE_OPEN  0x53552002U
#define SUCRUNE_PTY_MASTER_DROP 0x53552003U
#define SUCRUNE_PTY_IOCTL       0x53552004U
#define SUCRUNE_PTY_POLL        0x53552005U
#define SUCRUNE_PTY_MASTER_EXEC 0x53552006U /* args={number, 0 or FD_CLOEXEC} */
#define SUCRUNE_PTY_DESCRIBE    0x53552007U /* args={slave handle}; result=number */
#define SUCRUNE_PTY_CONTROL_MASTER 0x53552008U /* args={owned slave handle}; temporary master right, result=number */
#define SUCRUNE_PTY_HANDLE_BASE 0x2000
static inline int sucrune_pty_slave_handle(int64_t value) {
    return value >= SUCRUNE_PTY_HANDLE_BASE && value < SUCRUNE_PTY_HANDLE_BASE + (int64_t)SUCRUNE_PTY_ENDPOINTS;
}
struct sucrune_pty_ofd;
struct sucrune_pty_broker {
    struct sucrune_pty_ofd *slots[SUCRUNE_PTY_ENDPOINTS];
    unsigned char exec_flags[SUCRUNE_PTY_ENDPOINTS];
};
/* The manager's per-process broker session owns its slot array; fork shares
 * OFDs (termios, status flags, byte queues) but copies the slot table. */
void sucrune_pty_broker_fork(struct sucrune_pty_broker *child, const struct sucrune_pty_broker *parent);
void sucrune_pty_broker_destroy(struct sucrune_pty_broker *);
void sucrune_pty_broker_exec(struct sucrune_pty_broker *);
int sucrune_pty_broker_claims(const struct sucrune_request *);
typedef void (*sucrune_pty_stat_reply)(struct sucrune_response *, const struct stat *);
void sucrune_pty_broker_dispatch(struct sucrune_pty_broker *, const struct sucrune_request *,
    struct sucrune_response *, int *right, sucrune_pty_stat_reply);
#endif
