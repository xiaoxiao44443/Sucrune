#ifndef SUCRUNE_GUEST_THREADS_H
#define SUCRUNE_GUEST_THREADS_H
#include "guest_context.h"
#include "guest_signals.h"
#include <stddef.h>
#include <stdint.h>

#define SUCRUNE_THREAD_CHILD_LIMIT 63U
struct sucrune_thread_group;
struct sucrune_guest_thread;

/* All callbacks run with this Bionic pthread's host TLS. prepare and TID
 * callbacks run outside signal context; signal runs inside the signal gate.
 * Callbacks may take short process-state locks. clone must never be called
 * while holding a lock needed by any callback. Return 0 or negative errno. */
struct sucrune_thread_callbacks {
    int (*prepare)(void *user, struct sucrune_guest_thread *thread);
    void (*signal)(void *user, struct sucrune_guest_thread *thread,
                   int number, siginfo_t *info, void *native_context);
    int (*write_tid)(void *user, uintptr_t address, int32_t tid);
    /* Called after actual host pthread_join. Validate the address, release-
     * store zero, and FUTEX_WAKE (shared, not PRIVATE), count 1. Never replace
     * the Bionic thread's kernel clear_child_tid or robust-list pointers. */
    int (*clear_tid)(void *user, uintptr_t address);
};

struct sucrune_thread_stats {
    unsigned int live, peak, created, joined;
    int cleanup_error;
};

/* Host supervisor calls create/destroy, never a signal handler. One group
 * reserves SIGUSR2 in a dedicated runner process. destroy requires all guest
 * children to terminate normally; an exit_group path instead lets the runner
 * exit without freeing live mappings and proves cleanup by parent waitpid.
 * Initial guest execution must have stopped submitting clones before destroy;
 * destroy is not an externally concurrent cancellation API. */
int sucrune_threads_create(const struct sucrune_thread_callbacks *callbacks,
                          void *user, struct sucrune_thread_group **group);
int sucrune_threads_join(struct sucrune_thread_group *group);
int sucrune_threads_destroy(struct sucrune_thread_group *group);
void sucrune_threads_stats(struct sucrune_thread_group *group,
                           struct sucrune_thread_stats *stats);

/* Validates only flags/ABI shape; root validates guest SP/TLS/TID pointers
 * against its VMA table before calling. Copies cpu into a bounded slot, then
 * asks the unfiltered supervisor to pthread_create and waits with raw futex.
 * Safe only after the signal gate has restored host TLS. On success parent
 * receives the host TID; child resumes cpu with x0=0, SP=stack, TLS=tls.
 * clone3 should return ENOSYS separately so glibc falls back to clone. */
int64_t sucrune_threads_clone(struct sucrune_thread_group *group,
    uint64_t flags, uintptr_t stack, uintptr_t parent_tid, uintptr_t tls,
    uintptr_t child_tid, uint64_t signal_mask, const struct sucrune_signal_cpu *cpu);

/* These accessors are usable after restoring host TLS; current is NULL on
 * threads not created by this module (including the initial guest thread). */
struct sucrune_guest_thread *sucrune_thread_current(void);
struct sucrune_signal_gate *sucrune_thread_gate(struct sucrune_guest_thread *thread);
int64_t sucrune_thread_tid(const struct sucrune_guest_thread *thread);
int sucrune_thread_on_altstack(const struct sucrune_guest_thread *thread, uintptr_t address);
uint64_t *sucrune_thread_signal_mask(struct sucrune_guest_thread *thread);
struct sucrune_signal_thread *sucrune_thread_signals(struct sucrune_guest_thread *thread);
void sucrune_thread_set_clear_tid(struct sucrune_guest_thread *thread, uintptr_t address);
/* Redirect a SIGSYS frame to the saved host return path; this ends only this
 * guest thread. The supervisor joins it before clearing/waking guest TID. */
void sucrune_thread_exit(struct sucrune_guest_thread *thread, void *native_context);

/* ARM64 normalized CPU adapters. Copy GPRs/NZCV/FPSIMD only; retain the host
 * signal-frame layout, uc_stack and signal mask. Active SVE/SME or unknown
 * extended state returns ENOTSUP instead of silently truncating registers. */
int sucrune_thread_cpu_capture(const void *native_context, struct sucrune_signal_cpu *cpu);
int sucrune_thread_cpu_apply(void *native_context, const struct sucrune_signal_cpu *cpu);
#endif
