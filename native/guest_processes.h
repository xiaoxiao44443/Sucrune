#ifndef SUCRUNE_GUEST_PROCESSES_H
#define SUCRUNE_GUEST_PROCESSES_H
#include "guest_fds.h"
#include "guest_abi.h"
#include "guest_network.h"
#include "guest_signals.h"
#include "guest_space.h"
#include "pty_runtime.h"
#include <stdint.h>

#define SUCRUNE_PROCESS_LIMIT 16U
struct sucrune_process_group;
struct rusage;
struct sucrune_vfork_lease { int read_fd; void *arena; };
struct sucrune_process_snapshot {
    struct sucrune_signal_cpu cpu;
    uintptr_t tls, child_tid;
    uint64_t flags;
    const struct sucrune_guest_space *space, *fixed_space;
    const struct sucrune_fd_table *descriptors;
    const struct sucrune_guest_network *network;
    int broker;
    struct sucrune_project_owner owner;
    uint64_t signal_mask;
    struct sucrune_signal_stack signal_stack;
    const struct sucrune_signal_process *signal_actions;
    const struct sucrune_pty_table *ptys;
    const char *runner;
    unsigned int linux_jit, exec_depth, trace_syscalls, trace_faults, build_profile;
};
struct sucrune_process_stats { unsigned int created, waited, cleanup_reaped, killed, live, peak; };
/* Eventfd stays owned by the group. Only the signal bridge consumes a notice.
 * Standard SIGCHLD coalesces. Reaping via wait4 remains a separate operation. */
int sucrune_processes_wake_fd(const struct sucrune_process_group *group);
int sucrune_processes_take_child_signal(struct sucrune_process_group *group,struct sucrune_signal_info *info);

/* Create before guest filters are installed. Dedicated supervisor remains alive
 * until destruction; its death delivers SIGKILL to each direct fork child. */
int sucrune_processes_create(struct sucrune_process_group **out);
/* Caller HOLDS its process-state lock across this entire call. The supervisor
 * performs Bionic fork without taking it. The COW snapshot includes the calling
 * guest's actual address space. The child uses a separate raw dispatcher which
 * never takes copied host locks. cpu is captured from trapped clone ucontext;
 * tls is gate->last_guest_tpidr, x18 is cpu.regs[18]. Supports stack==0 at
 * caller and SIGCHLD plus optional CHILD_SETTID/CHILD_CLEARTID. The special
 * CLONE_VM|CLONE_VFORK path shares guest pages and returns a completion lease.
 * Broker files reference the same kernel open descriptions in a new session. */
int64_t sucrune_processes_fork(struct sucrune_process_group *group,
                               const struct sucrune_process_snapshot *snapshot,
                               struct sucrune_vfork_lease *lease);
/* After releasing the process-state lock, suspend the cloning guest thread
 * until the kernel closes the child's private writer on successful exec or
 * exit. Other guest threads and the broker remain runnable. */
void sucrune_processes_finish_vfork(struct sucrune_vfork_lease *lease);
/* pid>0 or -1 (registered children only), WNOHANG/WUNTRACED/WCONTINUED,
 * with optional kernel rusage. Stopped/continued states come from waitid; the existing guest
 * SIGCHLD notification reports exits. Release caller state lock before
 * this blocking operation. status is host storage. Return PID, 0 for WNOHANG,
 * or negative errno. Recheck guest status copyout memory after reacquiring. */
int64_t sucrune_processes_wait(struct sucrune_process_group *group,
                               int64_t pid, unsigned int options, int *status, struct rusage *usage);
/* Kernel process/session group query; 0/self or a still-owned child only. */
int64_t sucrune_processes_query_group(struct sucrune_process_group *group, int64_t pid, int session);
/* These operations pin registered child identities against waitpid/reuse
 * through the kernel call. 0 has the ordinary Linux meaning for setpgid. */
int sucrune_processes_set_group(struct sucrune_process_group *, int32_t pid, int32_t pgid);
int sucrune_processes_set_foreground(struct sucrune_process_group *, int tty, int32_t pgid);
/* Identity is authorized while holding the same mutex as waitpid. Only this
 * runner and its direct, unreaped children can produce host proc descriptors.
 * Kind 0 opens the PID directory O_PATH, 1 opens stat for reading, and 2
 * opens stat O_PATH for metadata. No host handle is published to the guest. */
int sucrune_processes_proc_pids(struct sucrune_process_group *group,int32_t *pids,size_t capacity);
int sucrune_processes_open_proc(struct sucrune_process_group *group,int32_t pid,int stat_file);
/* Positive direct child only. Signal zero checks existence (including a
 * waitable zombie); SIGKILL and SIGCONT use the host kernel. Never signals groups. */
int sucrune_processes_signal_child(struct sucrune_process_group *group,int32_t pid,int32_t signo);
/* Call once after guest submissions have stopped. Terminates/reaps outstanding
 * owned children before joining the supervisor, then frees group state. */
int sucrune_processes_destroy(struct sucrune_process_group *group,
                              struct sucrune_process_stats *stats);
#endif
