#include "probe.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <ucontext.h>
#include <unistd.h>

#if defined(__aarch64__)
#define PROBE_ABI "arm64-v8a"
#define PROBE_AUDIT_ARCH AUDIT_ARCH_AARCH64
#elif defined(__x86_64__)
#define PROBE_ABI "x86_64"
#define PROBE_AUDIT_ARCH AUDIT_ARCH_X86_64
#else
#error "Sucrune's initial probe supports only arm64 and x86_64."
#endif

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "The initial probe filter is for little-endian Android/Linux ABIs."
#endif

#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif

#define PROBE_RETURN 424242L
#define PROBE_TAG 0x5347U

_Static_assert(ATOMIC_LONG_LOCK_FREE == 2,
               "Signal handler requires lock-free pointer-sized atomics.");

extern long sucrune_probe_getpid(void);
extern void sucrune_probe_resume(void);

static pthread_mutex_t probe_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile sig_atomic_t handler_active;
static volatile sig_atomic_t trap_count;
static volatile sig_atomic_t signal_syscall;
static volatile sig_atomic_t signal_arch;
static volatile sig_atomic_t on_alt_stack;
static _Atomic uintptr_t alt_stack_start;
static _Atomic uintptr_t alt_stack_end;

struct probe_state {
    const char *status;
    const char *stage;
    const char *message;
    int error_number;
    long page_size;
    long process_id;
    long process_uid;
    int inherited_seccomp;
    int inherited_no_new_privs;
    int worker_no_new_privs;
    long baseline_pid;
    long observed_return;
    long control_pid;
    long control_tid_before;
    long control_tid_after;
    bool filter_installed;
    bool thread_joined;
    bool handler_restored;
    void *alt_mapping;
    size_t alt_mapping_size;
    char kernel[sizeof(((struct utsname *)0)->release)];
};

static void fail(struct probe_state *state, const char *stage,
                 const char *message, int error_number) {
    state->status = "failed";
    state->stage = stage;
    state->message = message;
    state->error_number = error_number;
}

/* This function deliberately performs no allocation, logging, JNI/Go call,
 * locking, or syscall replay. Unexpected SIGSYS is fatal in this disposable
 * process; it must never turn an Android policy rejection into fake success.
 */
static void handle_sigsys(int number, siginfo_t *info, void *context) {
    if (number != SIGSYS || info == NULL || context == NULL ||
        handler_active != 1 || info->si_code != SYS_SECCOMP ||
        info->si_errno != (int)PROBE_TAG ||
        info->si_syscall != SYS_getpid ||
        info->si_arch != (unsigned int)PROBE_AUDIT_ARCH) {
        _exit(128 + SIGSYS);
    }

    unsigned char stack_marker;
    uintptr_t address = (uintptr_t)&stack_marker;
    uintptr_t start = atomic_load_explicit(&alt_stack_start, memory_order_relaxed);
    uintptr_t end = atomic_load_explicit(&alt_stack_end, memory_order_relaxed);
    on_alt_stack = (address >= start && address < end) ? 1 : 0;
    if (trap_count < INT_MAX) {
        trap_count++;
    }
    signal_syscall = (sig_atomic_t)info->si_syscall;
    signal_arch = (sig_atomic_t)info->si_arch;

    ucontext_t *registers = (ucontext_t *)context;
#if defined(__aarch64__)
    registers->uc_mcontext.regs[0] = (unsigned long)PROBE_RETURN;
#elif defined(__x86_64__)
    registers->uc_mcontext.gregs[REG_RAX] = (greg_t)PROBE_RETURN;
#endif
    /* Returning uses the platform's signal restorer and rt_sigreturn. */
}

static int install_probe_filter(void) {
    uintptr_t resume = (uintptr_t)&sucrune_probe_resume;
    uint32_t low = (uint32_t)resume;
    uint32_t high = (uint32_t)(resume >> 32U);
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PROBE_AUDIT_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getpid, 0, 5),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, instruction_pointer) + 4U),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, high, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, instruction_pointer)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, low, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP | PROBE_TAG),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(instructions) / sizeof(instructions[0])),
        .filter = instructions,
    };
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program, 0UL, 0UL);
}

static void *run_worker(void *argument) {
    struct probe_state *state = (struct probe_state *)argument;
    if (state->page_size <= 0 || state->page_size > 1024 * 1024) {
        fail(state, "page_size", "Could not determine a valid host page size.", EINVAL);
        return NULL;
    }
    size_t page = (size_t)state->page_size;
    size_t usable = ((64U * 1024U + page - 1U) / page) * page;
    state->alt_mapping_size = usable + 2U * page;
    state->alt_mapping = mmap(NULL, state->alt_mapping_size, PROT_NONE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (state->alt_mapping == MAP_FAILED) {
        state->alt_mapping = NULL;
        fail(state, "signal_stack_map", "Could not allocate the alternate signal stack.", errno);
        return NULL;
    }
    void *stack_memory = (unsigned char *)state->alt_mapping + page;
    if (mprotect(stack_memory, usable, PROT_READ | PROT_WRITE) != 0) {
        fail(state, "signal_stack_protect", "Could not enable the alternate signal stack.", errno);
        return NULL;
    }
    stack_t stack = { .ss_sp = stack_memory, .ss_size = usable, .ss_flags = 0 };
    if (sigaltstack(&stack, NULL) != 0) {
        fail(state, "signal_stack_install", "Could not install the alternate signal stack.", errno);
        return NULL;
    }
    atomic_store_explicit(&alt_stack_start, (uintptr_t)stack_memory, memory_order_relaxed);
    atomic_store_explicit(&alt_stack_end, (uintptr_t)stack_memory + usable, memory_order_relaxed);

    sigset_t allowed;
    sigemptyset(&allowed);
    sigaddset(&allowed, SIGSYS);
    int error = pthread_sigmask(SIG_UNBLOCK, &allowed, NULL);
    if (error != 0) {
        fail(state, "signal_mask", "Could not unblock SIGSYS on the probe thread.", error);
        return NULL;
    }
    state->baseline_pid = sucrune_probe_getpid();
    state->control_tid_before = syscall(SYS_gettid);
    if (state->baseline_pid != state->process_id || state->control_tid_before <= 0) {
        fail(state, "baseline", "The unfiltered control syscalls failed.", 0);
        return NULL;
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) != 0) {
        fail(state, "no_new_privs", "The host rejected PR_SET_NO_NEW_PRIVS.", errno);
        return NULL;
    }
    state->worker_no_new_privs = prctl(PR_GET_NO_NEW_PRIVS, 0UL, 0UL, 0UL, 0UL);
    if (state->worker_no_new_privs != 1) {
        fail(state, "no_new_privs_verify", "PR_GET_NO_NEW_PRIVS did not confirm the requested state.", errno);
        return NULL;
    }
    handler_active = 1;
    if (install_probe_filter() != 0) {
        int saved_error = errno;
        fail(state, "seccomp_install", "The host rejected the probe's seccomp filter.", saved_error);
        if (saved_error == EACCES || saved_error == EPERM ||
            saved_error == EINVAL || saved_error == ENOSYS) {
            state->status = "unsupported";
        }
        return NULL;
    }
    state->filter_installed = true;
    state->observed_return = sucrune_probe_getpid();
    /* Same syscall from a different instruction address must remain real. */
    state->control_pid = syscall(SYS_getpid);
    state->control_tid_after = syscall(SYS_gettid);
    if (state->observed_return != PROBE_RETURN || trap_count != 1 ||
        on_alt_stack != 1 || state->control_pid != state->process_id ||
        state->control_tid_before != state->control_tid_after) {
        fail(state, "round_trip", "Trap, register restoration, or control-call verification failed.", 0);
        return NULL;
    }
    state->status = "passed";
    state->stage = "complete";
    state->message = "The selected syscall trapped and resumed with the synthetic result; control calls remained real.";
    /* The filter cannot be removed. It dies with this thread. Keep its stack
     * mapping alive until pthread_join confirms the kernel thread has exited.
     */
    return NULL;
}

static void escape_json(const char *source, char *destination, size_t capacity) {
    static const char digits[] = "0123456789abcdef";
    size_t used = 0;
    for (const unsigned char *p = (const unsigned char *)source; *p != 0; ++p) {
        unsigned char c = *p;
        if (c == '"' || c == '\\') {
            if (used + 2U >= capacity) break;
            destination[used++] = '\\';
            destination[used++] = (char)c;
        } else if (c < 0x20U || c >= 0x7fU) {
            if (used + 6U >= capacity) break;
            destination[used++] = '\\';
            destination[used++] = 'u';
            destination[used++] = '0';
            destination[used++] = '0';
            destination[used++] = digits[c >> 4U];
            destination[used++] = digits[c & 0xfU];
        } else {
            if (used + 1U >= capacity) break;
            destination[used++] = (char)c;
        }
    }
    destination[used] = '\0';
}

static void make_report(const struct probe_state *state, char *report, size_t capacity) {
    char kernel[6U * sizeof(state->kernel) + 1U];
    escape_json(state->kernel, kernel, sizeof(kernel));
    int length = snprintf(report, capacity,
        "{\"schema_version\":1,\"probe\":\"seccomp_sigsys_return\","
        "\"status\":\"%s\",\"stage\":\"%s\",\"error_number\":%d,\"message\":\"%s\","
        "\"host\":{\"abi\":\"%s\",\"kernel\":\"%s\",\"page_size\":%ld,"
        "\"pid\":%ld,\"uid\":%ld,\"seccomp_mode\":%d,\"no_new_privs\":%d},"
        "\"evidence\":{\"filter_installed\":%s,\"worker_no_new_privs\":%d,"
        "\"expected_return\":%ld,\"observed_return\":%ld,\"trap_count\":%d,"
        "\"syscall_number\":%d,\"signal_syscall\":%d,\"signal_arch\":%" PRIu32 ","
        "\"on_alt_stack\":%s,\"baseline_pid\":%ld,\"control_pid\":%ld,"
        "\"control_tid_before\":%ld,\"control_tid_after\":%ld,"
        "\"handler_restored\":%s,\"thread_joined\":%s}}",
        state->status, state->stage, state->error_number, state->message,
        PROBE_ABI, kernel, state->page_size, state->process_id, state->process_uid,
        state->inherited_seccomp, state->inherited_no_new_privs,
        state->filter_installed ? "true" : "false", state->worker_no_new_privs,
        PROBE_RETURN, state->observed_return, (int)trap_count,
        (int)SYS_getpid, (int)signal_syscall, (uint32_t)signal_arch,
        on_alt_stack == 1 ? "true" : "false", state->baseline_pid, state->control_pid,
        state->control_tid_before, state->control_tid_after,
        state->handler_restored ? "true" : "false", state->thread_joined ? "true" : "false");
    if (length < 0 || (size_t)length >= capacity) {
        (void)snprintf(report, capacity,
            "{\"schema_version\":1,\"status\":\"failed\",\"stage\":\"report_buffer\"}");
    }
}

int sucrune_probe_run(char *report, size_t capacity) {
    if (report == NULL || capacity == 0) return 1;
    int lock_error = pthread_mutex_trylock(&probe_lock);
    if (lock_error != 0) {
        (void)snprintf(report, capacity,
            "{\"schema_version\":1,\"probe\":\"seccomp_sigsys_return\","
            "\"status\":\"failed\",\"stage\":\"busy\",\"error_number\":%d}", lock_error);
        return 1;
    }
    struct probe_state state = {
        .status = "failed", .stage = "initializing", .message = "The probe has not completed.",
        .observed_return = -1, .baseline_pid = -1, .control_pid = -1,
        .control_tid_before = -1, .control_tid_after = -1, .worker_no_new_privs = -1,
    };
    handler_active = 0;
    trap_count = 0;
    signal_syscall = -1;
    signal_arch = 0;
    on_alt_stack = 0;
    state.page_size = sysconf(_SC_PAGESIZE);
    state.process_id = syscall(SYS_getpid);
    state.process_uid = (long)getuid();
    state.inherited_seccomp = prctl(PR_GET_SECCOMP, 0UL, 0UL, 0UL, 0UL);
    state.inherited_no_new_privs = prctl(PR_GET_NO_NEW_PRIVS, 0UL, 0UL, 0UL, 0UL);
    struct utsname system_name;
    if (uname(&system_name) == 0) {
        (void)snprintf(state.kernel, sizeof(state.kernel), "%s", system_name.release);
    } else {
        (void)snprintf(state.kernel, sizeof(state.kernel), "unknown");
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = handle_sigsys;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&action.sa_mask);
    struct sigaction previous;
    if (sigaction(SIGSYS, &action, &previous) != 0) {
        fail(&state, "signal_handler_install", "Could not install the SIGSYS handler.", errno);
    } else {
        pthread_t thread;
        int error = pthread_create(&thread, NULL, run_worker, &state);
        if (error != 0) {
            fail(&state, "thread_create", "Could not create the dedicated native probe thread.", error);
        } else {
            error = pthread_join(thread, NULL);
            if (error != 0) {
                /* Cannot safely restore a handler or release thread-owned state
                 * without proving that the filtered thread has terminated.
                 */
                _exit(120);
            }
            state.thread_joined = true;
        }
        handler_active = 0;
        if (sigaction(SIGSYS, &previous, NULL) != 0) {
            fail(&state, "signal_handler_restore", "Could not restore the previous SIGSYS handler.", errno);
        } else {
            state.handler_restored = true;
        }
    }
    if (state.alt_mapping != NULL &&
        munmap(state.alt_mapping, state.alt_mapping_size) != 0) {
        fail(&state, "signal_stack_release", "Could not release the alternate signal stack.", errno);
    }
    make_report(&state, report, capacity);
    int result = strcmp(state.status, "passed") == 0 ? 0 : 1;
    (void)pthread_mutex_unlock(&probe_lock);
    return result;
}
