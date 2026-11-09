#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/* A real Linux/musl program. All pthread, TLS and futex operations below run
 * in the guest. The Android harness must also verify its cleanup barriers.
 * Default: 8 simultaneous children, 8 rounds, 64 successful joins.
 * exit-group: 8 children execute pure computation; main calls exit_group(37).
 */
enum { THREADS = 8, ROUNDS = 8, ITERATIONS = 256, EXIT_GROUP_STATUS = 37 };
static _Thread_local uint64_t tls_word = UINT64_C(0x73554352554e4500);
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static unsigned int ready, started;
static uint64_t mutex_count, mutex_checksum;
static _Atomic int futex_gate, futex_arrived, spinning;
static _Atomic unsigned int atomic_count, completed, waited;
static int exit_group_mode;
_Static_assert(sizeof(_Atomic int) == sizeof(int), "Linux futex word size");
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "guest counter must be lock free");

struct worker {
    unsigned int index, round;
    long tid;
    uintptr_t tls_address;
    uint64_t result;
    volatile uint64_t heartbeat;
};

static _Noreturn void fail(const char *stage, int error) {
    fprintf(stderr, "LINUX_THREAD_FAIL stage=%s error=%d\n", stage, error);
    fflush(stderr);
    (void)syscall(SYS_exit_group, 90);
    _Exit(91);
}
static void checked(int result, const char *stage) {
    if (result != 0) fail(stage, result);
}
static void wake_word(_Atomic int *word, const char *stage) {
    if (syscall(SYS_futex, (int *)(void *)word, FUTEX_WAKE_PRIVATE, INT_MAX, NULL, NULL, 0) < 0) fail(stage, errno);
}
static int wait_word(_Atomic int *word, int expected, const char *stage) {
    const struct timespec timeout = {.tv_sec = 5, .tv_nsec = 0};
    long result = syscall(SYS_futex, (int *)(void *)word, FUTEX_WAIT_PRIVATE,
        expected, &timeout, NULL, 0);
    if (result == 0) return 1;
    if (errno != EAGAIN && errno != EINTR) fail(stage, errno);
    return 0;
}
static uint64_t token_for(const struct worker *worker) {
    return ((uint64_t)(worker->round + 1U) << 32U) | (uint64_t)(worker->index + 1U);
}

static void *work(void *argument) {
    struct worker *worker = argument;
    const uint64_t token = token_for(worker);
    tls_word = token;
    worker->tls_address = (uintptr_t)&tls_word;
    worker->tid = syscall(SYS_gettid);
    if (worker->tid <= 0) fail("gettid", errno);
    checked(pthread_mutex_lock(&mutex), "ready-lock");
    ready++;
    /* Main and children wait for different predicates on this condition.
     * Broadcast avoids waking only another child and stranding main. */
    checked(pthread_cond_broadcast(&condition), "ready-signal");
    while (started == 0U) checked(pthread_cond_wait(&condition, &mutex), "start-wait");
    checked(pthread_mutex_unlock(&mutex), "ready-unlock");
    if (tls_word != token) fail("tls-start", (int)worker->index);

    if (exit_group_mode) {
        /* No syscall or cancellation point follows this publication. The
         * supervisor must terminate the entire process, not just main. */
        atomic_fetch_add_explicit(&spinning, 1, memory_order_release);
        uint64_t value = token;
        for (;;) {
            value ^= value << 13U;
            value ^= value >> 7U;
            value ^= value << 17U;
            worker->heartbeat = value;
        }
    }

    atomic_fetch_add_explicit(&futex_arrived, 1, memory_order_release);
    wake_word(&futex_arrived, "arrived-wake");
    while (atomic_load_explicit(&futex_gate, memory_order_acquire) == 0) {
        if (wait_word(&futex_gate, 0, "gate-wait")) atomic_fetch_add_explicit(&waited, 1U, memory_order_relaxed);
    }
    for (unsigned int i = 0U; i < ITERATIONS; i++) {
        if (tls_word != token) fail("tls-loop", (int)worker->index);
        atomic_fetch_add_explicit(&atomic_count, 1U, memory_order_relaxed);
        checked(pthread_mutex_lock(&mutex), "count-lock");
        mutex_count++;
        mutex_checksum += token;
        checked(pthread_mutex_unlock(&mutex), "count-unlock");
    }
    worker->result = tls_word;
    atomic_fetch_add_explicit(&completed, 1U, memory_order_release);
    return (void *)(uintptr_t)token;
}

static void wait_for_spinners(void) {
    struct timespec began, now;
    if (clock_gettime(CLOCK_MONOTONIC, &began) != 0) fail("spin-clock", errno);
    unsigned int polls = 0U;
    while (atomic_load_explicit(&spinning, memory_order_acquire) != THREADS) {
        if (++polls == 100000U) {
            polls = 0U;
            if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) fail("spin-clock", errno);
            if (now.tv_sec - began.tv_sec >= 5) fail("spin-ready-timeout", ETIMEDOUT);
        }
    }
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "exit-group") == 0) exit_group_mode = 1;
    else if (argc != 1) {
        fputs("usage: linux-thread-smoke [exit-group]\n", stderr);
        return 2;
    }
    const uint64_t main_token = UINT64_C(0x53554352554e454d);
    const long main_tid = syscall(SYS_gettid);
    tls_word = main_token;
    unsigned int joined = 0U;
    uint64_t expected_checksum = 0U;
    for (unsigned int round = 0U; round < (exit_group_mode ? 1U : ROUNDS); round++) {
        pthread_t handles[THREADS];
        struct worker workers[THREADS] = {0};
        ready = 0U; started = 0U;
        atomic_store_explicit(&futex_gate, 0, memory_order_relaxed);
        atomic_store_explicit(&futex_arrived, 0, memory_order_relaxed);
        for (unsigned int i = 0U; i < THREADS; i++) {
            workers[i].index = i; workers[i].round = round;
            checked(pthread_create(&handles[i], NULL, work, &workers[i]), "pthread-create");
            expected_checksum += token_for(&workers[i]) * ITERATIONS;
        }
        checked(pthread_mutex_lock(&mutex), "main-lock");
        while (ready != THREADS) checked(pthread_cond_wait(&condition, &mutex), "ready-wait");
        /* Every child remains live behind the same condition barrier here.
         * Their TLS addresses must differ within the round; reuse between
         * fully joined rounds is deliberately allowed. */
        for (unsigned int i = 0U; i < THREADS; i++) {
            if (workers[i].tid == main_tid || workers[i].tls_address == (uintptr_t)&tls_word) fail("tls-main-alias", (int)i);
            for (unsigned int j = 0U; j < i; j++) {
                if (workers[i].tid == workers[j].tid || workers[i].tls_address == workers[j].tls_address) fail("thread-alias", (int)i);
            }
        }
        started = 1U;
        checked(pthread_cond_broadcast(&condition), "start-broadcast");
        checked(pthread_mutex_unlock(&mutex), "main-unlock");
        if (exit_group_mode) {
            wait_for_spinners();
            puts("LINUX_THREAD_EXIT_GROUP_READY spinning=8");
            fflush(stdout);
            (void)syscall(SYS_exit_group, EXIT_GROUP_STATUS);
            fail("exit-group-returned", 0);
        }
        for (;;) {
            int arrived = atomic_load_explicit(&futex_arrived, memory_order_acquire);
            if (arrived == THREADS) break;
            (void)wait_word(&futex_arrived, arrived, "arrived-wait");
        }
        atomic_store_explicit(&futex_gate, 1, memory_order_release);
        wake_word(&futex_gate, "gate-wake");
        for (unsigned int i = 0U; i < THREADS; i++) {
            void *result = NULL;
            checked(pthread_join(handles[i], &result), "pthread-join");
            if ((uintptr_t)result != (uintptr_t)token_for(&workers[i]) || workers[i].result != token_for(&workers[i])) fail("join-result", (int)i);
            joined++;
        }
        if (tls_word != main_token || syscall(SYS_gettid) != main_tid) fail("main-tls-preserved", (int)round);
        unsigned int expected = (round + 1U) * THREADS * ITERATIONS;
        if (atomic_load_explicit(&atomic_count, memory_order_relaxed) != expected || mutex_count != expected || mutex_checksum != expected_checksum) fail("counter-mismatch", (int)round);
        if (atomic_load_explicit(&completed, memory_order_acquire) != joined) fail("completed-mismatch", (int)round);
    }
    checked(pthread_cond_destroy(&condition), "cond-destroy");
    checked(pthread_mutex_destroy(&mutex), "mutex-destroy");
    printf("LINUX_THREAD_OK parallel=8 rounds=8 joined=%u atomic=%u mutex=%llu tls=independent cond futex waits=%u\n",
        joined, atomic_load_explicit(&atomic_count, memory_order_relaxed), (unsigned long long)mutex_count,
        atomic_load_explicit(&waited, memory_order_relaxed));
    return 0;
}
