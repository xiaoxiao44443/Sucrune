#ifndef SUCRUNE_GUEST_GATES_H
#define SUCRUNE_GUEST_GATES_H

#include "guest_context.h"

#define SUCRUNE_GATE_CAPACITY 64U

/* Assembly-visible arrays. A slot is published by release-storing its TID
 * after its fully initialized gate pointer. Signal entry first matches its
 * own raw gettid against an acquired TID, and only then reads the pointer.
 * Other threads therefore never dereference gates being retired elsewhere. */
extern _Atomic(struct sucrune_signal_gate *) sucrune_signal_gate_slots[SUCRUNE_GATE_CAPACITY];
extern _Atomic(int64_t) sucrune_signal_gate_tids[SUCRUNE_GATE_CAPACITY];
extern _Atomic(unsigned int) sucrune_signal_gate_count;

/* Host-side operations only, never call these before restoring host TLS.
 * Gate identity/host/handler must be initialized before registration and must
 * remain immutable while registered. Host context must be ready before the
 * owner can enter guest code. Register returns a slot index or negative errno;
 * registering the same gate again returns the same slot, a conflicting TID
 * returns EEXIST, and a full table returns EAGAIN. Writers are serialized by a
 * short atomic-flag lock. The signal lookup path never takes that lock. */
int sucrune_gate_register(struct sucrune_signal_gate *gate);

/* Unregister only after the owner has exited or reached a host path guaranteed
 * never to re-enter this gate. After unregister returns, memory may be freed
 * only when no external C find() borrower can still hold it. Clear and quiesce
 * the legacy global separately if it also points at this gate. */
int sucrune_gate_unregister(struct sucrune_signal_gate *gate);

/* Borrowed pointer: caller must ensure lifetime until use finishes. Registered
 * gates take precedence; the old global is the fallback for its matching TID.
 * Do not publish conflicting contexts for one TID in the legacy global/table.
 * Old single-thread callers can continue to use the global alone unchanged. */
struct sucrune_signal_gate *sucrune_gate_find(int64_t thread_id);

_Static_assert(SUCRUNE_GATE_CAPACITY == 64U, "signal_gate.S table bound");
_Static_assert(sizeof(_Atomic(struct sucrune_signal_gate *)) == 8U, "assembly pointer stride");
_Static_assert(sizeof(_Atomic(int64_t)) == 8U, "assembly TID stride");
_Static_assert(sizeof(_Atomic(unsigned int)) == 4U, "assembly registry count size");
_Static_assert(_Alignof(_Atomic(struct sucrune_signal_gate *)) >= 8U, "assembly pointer alignment");
_Static_assert(_Alignof(_Atomic(int64_t)) >= 8U, "assembly TID alignment");
_Static_assert(_Alignof(_Atomic(unsigned int)) >= 4U, "assembly registry count alignment");
#if defined(SUCRUNE_GATE_HOST_TEST) && defined(_MSC_VER)
_Static_assert(ATOMIC_LLONG_LOCK_FREE >= 1, "host TID atomics must support lock-free operation");
_Static_assert(ATOMIC_INT_LOCK_FREE >= 1, "host count atomics must support lock-free operation");
#else
_Static_assert(ATOMIC_LLONG_LOCK_FREE == 2, "signal TID lookup must be lock free");
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "signal registry count must be lock free");
#endif

#endif
