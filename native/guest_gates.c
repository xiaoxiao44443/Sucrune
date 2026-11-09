#include "guest_gates.h"
#include <errno.h>

/* ARM64 definitions live beside the legacy global in signal_gate.S. Keeping
 * them there preserves old assembly-only probe links. Non-ARM64 builds need
 * definitions for the management build and portable ownership unit tests. */
#if !defined(__aarch64__)
_Atomic(struct sucrune_signal_gate *) sucrune_active_signal_gate;
_Atomic(struct sucrune_signal_gate *) sucrune_signal_gate_slots[SUCRUNE_GATE_CAPACITY];
_Atomic(int64_t) sucrune_signal_gate_tids[SUCRUNE_GATE_CAPACITY];
_Atomic(unsigned int) sucrune_signal_gate_count;
#endif

static atomic_flag writers = ATOMIC_FLAG_INIT;
static void lock_writers(void) {
    while (atomic_flag_test_and_set_explicit(&writers, memory_order_acquire)) { }
}
static void unlock_writers(void) { atomic_flag_clear_explicit(&writers, memory_order_release); }

int sucrune_gate_register(struct sucrune_signal_gate *gate) {
    if (gate == NULL || gate->host == NULL || gate->handler == NULL || gate->thread_id <= 0) return -EINVAL;
    lock_writers();
    int vacant = -1;
    for (unsigned int i = 0U; i < SUCRUNE_GATE_CAPACITY; i++) {
        int64_t tid = atomic_load_explicit(&sucrune_signal_gate_tids[i], memory_order_relaxed);
        struct sucrune_signal_gate *existing = atomic_load_explicit(&sucrune_signal_gate_slots[i], memory_order_relaxed);
        if (existing == gate) {
            int result = tid == gate->thread_id ? (int)i : -EINVAL;
            unlock_writers(); return result;
        }
        if (tid == gate->thread_id) { unlock_writers(); return -EEXIST; }
        if (tid == 0 && existing == NULL && vacant < 0) vacant = (int)i;
    }
    if (vacant >= 0) {
        atomic_store_explicit(&sucrune_signal_gate_slots[vacant], gate, memory_order_release);
        atomic_store_explicit(&sucrune_signal_gate_tids[vacant], gate->thread_id, memory_order_release);
        atomic_fetch_add_explicit(&sucrune_signal_gate_count, 1U, memory_order_release);
    }
    unlock_writers();
    return vacant >= 0 ? vacant : -EAGAIN;
}

int sucrune_gate_unregister(struct sucrune_signal_gate *gate) {
    if (gate == NULL) return -EINVAL;
    lock_writers();
    for (unsigned int i = 0U; i < SUCRUNE_GATE_CAPACITY; i++) {
        struct sucrune_signal_gate *existing = atomic_load_explicit(&sucrune_signal_gate_slots[i], memory_order_relaxed);
        if (existing != gate) continue;
        /* No live owner may still be in lookup. Unrelated signal threads only
         * examine the sidecar TID, so clearing this slot cannot expose freed
         * gate fields to their scans. */
        atomic_store_explicit(&sucrune_signal_gate_tids[i], 0, memory_order_release);
        atomic_store_explicit(&sucrune_signal_gate_slots[i], NULL, memory_order_release);
        atomic_fetch_sub_explicit(&sucrune_signal_gate_count, 1U, memory_order_release);
        unlock_writers(); return 0;
    }
    unlock_writers(); return -ENOENT;
}

struct sucrune_signal_gate *sucrune_gate_find(int64_t thread_id) {
    if (thread_id <= 0) return NULL;
    for (unsigned int i = 0U; i < SUCRUNE_GATE_CAPACITY; i++) {
        if (atomic_load_explicit(&sucrune_signal_gate_tids[i], memory_order_acquire) != thread_id) continue;
        struct sucrune_signal_gate *gate = atomic_load_explicit(&sucrune_signal_gate_slots[i], memory_order_acquire);
        if (gate != NULL && atomic_load_explicit(&sucrune_signal_gate_tids[i], memory_order_acquire) == thread_id &&
            gate->thread_id == thread_id) return gate;
    }
    struct sucrune_signal_gate *legacy = atomic_load_explicit(&sucrune_active_signal_gate, memory_order_acquire);
    return legacy != NULL && legacy->thread_id == thread_id ? legacy : NULL;
}
