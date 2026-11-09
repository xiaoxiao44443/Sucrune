#ifndef SUCRUNE_GUEST_CONTEXT_H
#define SUCRUNE_GUEST_CONTEXT_H

#include <stddef.h>
#include <stdint.h>
#include <signal.h>
#include <stdatomic.h>

/* Windows ownership tests never install POSIX handlers; use only an opaque
 * declaration so the exact gate layout remains testable with MSVC. */
#if defined(_MSC_VER) && defined(_WIN32)
typedef struct sucrune_test_siginfo siginfo_t;
#endif

/* Fixed assembly ABI. Host TLS must be restored before calling Android code. */
struct sucrune_host_context {
    uint64_t general[12], floating[8], sp, x18, fpcr, fpsr;
    uint64_t tpidr_el0, reserved;
};
_Static_assert(offsetof(struct sucrune_host_context, sp) == 160U, "host SP offset");
_Static_assert(offsetof(struct sucrune_host_context, x18) == 168U, "host x18 offset");
_Static_assert(offsetof(struct sucrune_host_context, tpidr_el0) == 192U, "host TLS offset");
_Static_assert(sizeof(struct sucrune_host_context) == 208U, "guest_entry.S ABI");

struct sucrune_signal_gate {
    struct sucrune_host_context *host;
    void (*handler)(int, siginfo_t *, void *);
    int64_t thread_id;
    uint64_t last_guest_tpidr, last_guest_x18, switches;
};
_Static_assert(offsetof(struct sucrune_signal_gate, handler) == 8U, "gate callback offset");
_Static_assert(offsetof(struct sucrune_signal_gate, thread_id) == 16U, "gate TID offset");
_Static_assert(offsetof(struct sucrune_signal_gate, last_guest_tpidr) == 24U, "gate TLS evidence offset");
_Static_assert(offsetof(struct sucrune_signal_gate, switches) == 40U, "gate count offset");
_Static_assert(sizeof(struct sucrune_signal_gate) == 48U, "signal_gate.S gate ABI");
#if defined(SUCRUNE_GATE_HOST_TEST) && defined(_MSC_VER)
/* MSVC advertises 'sometimes' even for aligned 64-bit atomics. The host-only
 * test checks atomic_is_lock_free on every actual object before testing. */
_Static_assert(ATOMIC_POINTER_LOCK_FREE >= 1, "host pointer atomics must support lock-free operation");
#else
_Static_assert(ATOMIC_POINTER_LOCK_FREE == 2, "signal gate pointer must be lock free");
#endif

extern _Atomic(struct sucrune_signal_gate *) sucrune_active_signal_gate;
extern void sucrune_signal_entry(int number, siginfo_t *info, void *context);
extern void sucrune_guest_fatal_signal(int number);
extern int sucrune_guest_enter(uintptr_t entry, uintptr_t stack,
                              struct sucrune_host_context *host, int linux_abi);
extern void sucrune_guest_return(void);

#endif
