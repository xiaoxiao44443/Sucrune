#include "guest_gates.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
typedef HANDLE thread_handle;
typedef DWORD thread_result;
#define THREAD_CALL WINAPI
#define THREAD_RETURN return 0
static void yield_thread(void) { SwitchToThread(); }
static int launch(thread_handle *thread, thread_result (THREAD_CALL *body)(void *), void *argument) {
    *thread = CreateThread(NULL, 0U, body, argument, 0U, NULL);
    return *thread != NULL;
}
static int join(thread_handle thread) {
    DWORD code = 1U;
    int good = WaitForSingleObject(thread, 30000U) == WAIT_OBJECT_0 && GetExitCodeThread(thread, &code) && code == 0U;
    CloseHandle(thread); return good;
}
#else
#include <pthread.h>
#include <sched.h>
typedef pthread_t thread_handle;
typedef void *thread_result;
#define THREAD_CALL
#define THREAD_RETURN return NULL
static void yield_thread(void) { (void)sched_yield(); }
static int launch(thread_handle *thread, thread_result (*body)(void *), void *argument) {
    return pthread_create(thread, NULL, body, argument) == 0;
}
static int join(thread_handle thread) { return pthread_join(thread, NULL) == 0; }
#endif

#define CHECK(expression) do { if (!(expression)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expression); abort(); } } while (0)
static struct sucrune_signal_gate gates[SUCRUNE_GATE_CAPACITY + 1U];
static struct sucrune_host_context hosts[SUCRUNE_GATE_CAPACITY + 1U];
static unsigned int cases;
static void handler(int number, siginfo_t *info, void *context) { (void)number; (void)info; (void)context; }
static void initialize(struct sucrune_signal_gate *gate, struct sucrune_host_context *host, int64_t tid) {
    memset(host, 0, sizeof(*host)); memset(gate, 0, sizeof(*gate));
    host->tpidr_el0 = UINT64_C(0x1234567890abcdef); host->x18 = UINT64_C(0xfedcba0987654321);
    gate->host = host; gate->handler = handler; gate->thread_id = tid;
}
static unsigned int occupied(void) {
    unsigned int count = 0U;
    for (unsigned int i = 0U; i < SUCRUNE_GATE_CAPACITY; i++) {
        int64_t tid = atomic_load_explicit(&sucrune_signal_gate_tids[i], memory_order_acquire);
        struct sucrune_signal_gate *gate = atomic_load_explicit(&sucrune_signal_gate_slots[i], memory_order_acquire);
        CHECK((tid == 0) == (gate == NULL));
        if (tid != 0) { CHECK(gate->thread_id == tid); count++; }
    }
    CHECK(count == atomic_load_explicit(&sucrune_signal_gate_count, memory_order_acquire));
    return count;
}
static void finish(void) { CHECK(occupied() == 0U); CHECK(atomic_load(&sucrune_active_signal_gate) == NULL); cases++; }
static void invalid_and_empty(void) {
    CHECK(sucrune_gate_find(0) == NULL && sucrune_gate_find(-1) == NULL && sucrune_gate_find(17) == NULL);
    CHECK(sucrune_gate_register(NULL) == -EINVAL && sucrune_gate_unregister(NULL) == -EINVAL);
    initialize(&gates[0], &hosts[0], 1);
    gates[0].host = NULL; CHECK(sucrune_gate_register(&gates[0]) == -EINVAL);
    gates[0].host = &hosts[0]; gates[0].handler = NULL; CHECK(sucrune_gate_register(&gates[0]) == -EINVAL);
    gates[0].handler = handler; gates[0].thread_id = 0; CHECK(sucrune_gate_register(&gates[0]) == -EINVAL);
    gates[0].thread_id = -10; CHECK(sucrune_gate_register(&gates[0]) == -EINVAL);
    CHECK(sucrune_gate_unregister(&gates[0]) == -ENOENT);
    finish();
}
static void ownership_and_idempotence(void) {
    initialize(&gates[0], &hosts[0], 101);
    initialize(&gates[1], &hosts[1], 102);
    CHECK(sucrune_gate_register(&gates[0]) == 0);
    CHECK(sucrune_gate_register(&gates[0]) == 0 && occupied() == 1U);
    CHECK(sucrune_gate_register(&gates[1]) == 1);
    CHECK(sucrune_gate_find(101) == &gates[0] && sucrune_gate_find(102) == &gates[1]);
    CHECK(sucrune_gate_find(100) == NULL);
    gates[0].switches = 19U;
    CHECK(sucrune_gate_find(101)->switches == 19U);
    CHECK(sucrune_gate_unregister(&gates[0]) == 0 && sucrune_gate_find(101) == NULL);
    CHECK(sucrune_gate_unregister(&gates[0]) == -ENOENT);
    CHECK(sucrune_gate_find(102) == &gates[1]);
    CHECK(sucrune_gate_unregister(&gates[1]) == 0);
    finish();
}
static void identity_conflict(void) {
    initialize(&gates[0], &hosts[0], 201); initialize(&gates[1], &hosts[1], 201);
    CHECK(sucrune_gate_register(&gates[0]) == 0);
    CHECK(sucrune_gate_register(&gates[1]) == -EEXIST && occupied() == 1U);
    CHECK(sucrune_gate_unregister(&gates[1]) == -ENOENT && sucrune_gate_find(201) == &gates[0]);
    CHECK(sucrune_gate_unregister(&gates[0]) == 0);
    CHECK(sucrune_gate_register(&gates[1]) == 0 && sucrune_gate_find(201) == &gates[1]);
    CHECK(sucrune_gate_unregister(&gates[1]) == 0);
    finish();
}
static void capacity_and_reuse(void) {
    for (unsigned int i = 0U; i <= SUCRUNE_GATE_CAPACITY; i++) initialize(&gates[i], &hosts[i], 1000 + i);
    for (unsigned int i = 0U; i < SUCRUNE_GATE_CAPACITY; i++) CHECK(sucrune_gate_register(&gates[i]) == (int)i);
    CHECK(occupied() == SUCRUNE_GATE_CAPACITY);
    CHECK(sucrune_gate_register(&gates[SUCRUNE_GATE_CAPACITY]) == -EAGAIN);
    CHECK(sucrune_gate_unregister(&gates[31]) == 0);
    CHECK(sucrune_gate_register(&gates[SUCRUNE_GATE_CAPACITY]) == 31);
    CHECK(sucrune_gate_find(1064) == &gates[SUCRUNE_GATE_CAPACITY]);
    for (unsigned int i = 0U; i <= SUCRUNE_GATE_CAPACITY; i++) if (i != 31U) CHECK(sucrune_gate_unregister(&gates[i]) == 0);
    finish();
}
static void legacy_compatibility(void) {
    initialize(&gates[0], &hosts[0], 301); initialize(&gates[1], &hosts[1], 302);
    atomic_store_explicit(&sucrune_active_signal_gate, &gates[0], memory_order_release);
    CHECK(sucrune_gate_find(301) == &gates[0] && sucrune_gate_find(302) == NULL);
    CHECK(sucrune_gate_register(&gates[1]) == 0);
    CHECK(sucrune_gate_find(301) == &gates[0] && sucrune_gate_find(302) == &gates[1]);
    CHECK(sucrune_gate_register(&gates[0]) == 1);
    CHECK(sucrune_gate_unregister(&gates[0]) == 0 && sucrune_gate_find(301) == &gates[0]);
    atomic_store_explicit(&sucrune_active_signal_gate, NULL, memory_order_release);
    CHECK(sucrune_gate_find(301) == NULL);
    CHECK(sucrune_gate_unregister(&gates[1]) == 0);
    finish();
}
static void registered_lookup_avoids_legacy_dereference(void) {
    initialize(&gates[0], &hosts[0], 401);
    CHECK(sucrune_gate_register(&gates[0]) == 0);
    /* If registered lookup ever touches the legacy pointer, this isolated unit
     * process faults. This does not make an invalid legacy pointer supported. */
    atomic_store_explicit(&sucrune_active_signal_gate, (struct sucrune_signal_gate *)(uintptr_t)1U, memory_order_release);
    CHECK(sucrune_gate_find(401) == &gates[0]);
    atomic_store_explicit(&sucrune_active_signal_gate, NULL, memory_order_release);
    CHECK(sucrune_gate_unregister(&gates[0]) == 0);
    finish();
}

struct churn_state { struct sucrune_signal_gate gate; struct sucrune_host_context host; };
static struct churn_state churn[8];
static thread_result THREAD_CALL churn_thread(void *argument) {
    struct churn_state *state = argument;
    for (unsigned int i = 0U; i < 2000U; i++) {
        int slot = sucrune_gate_register(&state->gate);
        CHECK(slot >= 0 && slot < (int)SUCRUNE_GATE_CAPACITY);
        CHECK(sucrune_gate_find(state->gate.thread_id) == &state->gate);
        CHECK(sucrune_gate_register(&state->gate) == slot);
        CHECK(sucrune_gate_unregister(&state->gate) == 0);
        CHECK(sucrune_gate_find(state->gate.thread_id) == NULL);
    }
    THREAD_RETURN;
}
static void concurrent_churn(void) {
    thread_handle threads[8];
    for (unsigned int i = 0U; i < 8U; i++) {
        initialize(&churn[i].gate, &churn[i].host, 2000 + i);
        CHECK(launch(&threads[i], churn_thread, &churn[i]));
    }
    for (unsigned int i = 0U; i < 8U; i++) CHECK(join(threads[i]));
    finish();
}

static atomic_int contested_started, contested_attempted, contested_winners;
static thread_result THREAD_CALL contested_thread(void *argument) {
    struct sucrune_signal_gate *gate = argument;
    atomic_fetch_add(&contested_started, 1);
    while (atomic_load(&contested_started) != 8) yield_thread();
    int result = sucrune_gate_register(gate);
    if (result >= 0) atomic_fetch_add(&contested_winners, 1);
    else CHECK(result == -EEXIST);
    atomic_fetch_add(&contested_attempted, 1);
    while (atomic_load(&contested_attempted) != 8) yield_thread();
    if (result >= 0) CHECK(sucrune_gate_unregister(gate) == 0);
    THREAD_RETURN;
}
static void concurrent_duplicate_tid(void) {
    thread_handle threads[8];
    atomic_store(&contested_started, 0); atomic_store(&contested_attempted, 0); atomic_store(&contested_winners, 0);
    for (unsigned int i = 0U; i < 8U; i++) {
        initialize(&gates[i], &hosts[i], 3001);
        CHECK(launch(&threads[i], contested_thread, &gates[i]));
    }
    for (unsigned int i = 0U; i < 8U; i++) CHECK(join(threads[i]));
    CHECK(atomic_load(&contested_winners) == 1);
    finish();
}

static atomic_int observed, cleared;
static thread_result THREAD_CALL publication_writer(void *argument) {
    (void)argument;
    for (int iteration = 1; iteration <= 1000; iteration++) {
        initialize(&gates[0], &hosts[0], 4001);
        hosts[0].general[0] = (uint64_t)iteration;
        hosts[0].general[1] = UINT64_C(0xfeed000000000000) | (uint64_t)iteration;
        CHECK(sucrune_gate_register(&gates[0]) >= 0);
        while (atomic_load_explicit(&observed, memory_order_acquire) != iteration) yield_thread();
        CHECK(sucrune_gate_unregister(&gates[0]) == 0);
        while (atomic_load_explicit(&cleared, memory_order_acquire) != iteration) yield_thread();
    }
    THREAD_RETURN;
}
static thread_result THREAD_CALL publication_reader(void *argument) {
    (void)argument;
    for (int iteration = 1; iteration <= 1000; iteration++) {
        struct sucrune_signal_gate *gate;
        do { gate = sucrune_gate_find(4001); if (gate == NULL) yield_thread(); } while (gate == NULL);
        CHECK(gate->host == &hosts[0] && gate->handler == handler && gate->thread_id == 4001);
        CHECK(gate->host->general[0] == (uint64_t)iteration);
        CHECK(gate->host->general[1] == (UINT64_C(0xfeed000000000000) | (uint64_t)iteration));
        atomic_store_explicit(&observed, iteration, memory_order_release);
        while (sucrune_gate_find(4001) != NULL) yield_thread();
        atomic_store_explicit(&cleared, iteration, memory_order_release);
    }
    THREAD_RETURN;
}
static void publication_ordering(void) {
    atomic_store(&observed, 0); atomic_store(&cleared, 0);
    thread_handle writer, reader;
    CHECK(launch(&reader, publication_reader, NULL));
    CHECK(launch(&writer, publication_writer, NULL));
    CHECK(join(writer) && join(reader));
    finish();
}
int main(void) {
    CHECK(atomic_is_lock_free(&sucrune_active_signal_gate));
    CHECK(atomic_is_lock_free(&sucrune_signal_gate_count));
    for (unsigned int i = 0U; i < SUCRUNE_GATE_CAPACITY; i++) {
        CHECK(atomic_is_lock_free(&sucrune_signal_gate_slots[i]));
        CHECK(atomic_is_lock_free(&sucrune_signal_gate_tids[i]));
    }
    invalid_and_empty(); ownership_and_idempotence(); identity_conflict();
    capacity_and_reuse(); legacy_compatibility(); registered_lookup_avoids_legacy_dereference();
    concurrent_churn(); concurrent_duplicate_tid(); publication_ordering();
    printf("Guest gate registry checks: %u/%u passed; 64 slots, legacy fallback, 16000 concurrent ownership cycles and 1000 publication handshakes.\n", cases, cases);
    return 0;
}
