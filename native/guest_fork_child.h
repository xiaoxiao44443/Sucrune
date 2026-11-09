#ifndef SUCRUNE_GUEST_FORK_CHILD_H
#define SUCRUNE_GUEST_FORK_CHILD_H
#include "guest_processes.h"
#include "guest_exec.h"
#include <sys/types.h>
/* Internal immutable launch, prepared while guest VMA/FD ownership is locked.
 * Child inherits distinct stable host aliases referencing original kernel OFDs. */
struct sucrune_fork_launch {
    struct sucrune_process_snapshot snapshot;
    pid_t parent_group, parent_session;
    int aliases[SUCRUNE_LINUX_FD_LIMIT];
    int handles[SUCRUNE_LINUX_FD_LIMIT];
    int broker;
    unsigned int fd_limit;
    unsigned int fd_flags[SUCRUNE_LINUX_FD_LIMIT];
    unsigned char proc_stat_resource[SUCRUNE_LINUX_FD_LIMIT];
    /* Bound loopback datagrams can be closed by the pre-exec child. Their
     * data path requires the full runner's destination/source checks. */
    unsigned char udp_resource[SUCRUNE_LINUX_FD_LIMIT];
    struct sucrune_exec_fd metadata[SUCRUNE_LINUX_FD_LIMIT];
};
_Noreturn void sucrune_fork_child_start(struct sucrune_fork_launch *launch,
                                        int receipt, pid_t expected_parent);
/* Raw CLONE_VM creates a separate process and file table. The caller keeps
 * the leased runtime-only reservation until completion fd EOF on exec/exit. */
long sucrune_vfork_child_start(const struct sucrune_fork_launch *launch, int receipt,
                              pid_t expected_parent, int completion_writer, void **arena);
void sucrune_vfork_release_arena(void *arena);
#endif
