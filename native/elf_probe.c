#include "elf_probe.h"
#include "elf_loader.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

#if defined(__aarch64__)
#include "guest_context.h"
#include <elf.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <ucontext.h>

#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif
#define ELF_TRAP_TAG 0x5345U
#define GUEST_STACK_SIZE (1024U * 1024U)
#define SIGNAL_STACK_SIZE (64U * 1024U)
#define OUTPUT_CAPACITY 256U

extern const unsigned char sucrune_hello_start[], sucrune_hello_end[];

_Static_assert(ATOMIC_POINTER_LOCK_FREE == 2, "signal pointer must be lock free");

struct elf_state {
    const char *status, *stage, *message;
    int error_number;
    long page_size;
    struct sucrune_elf_image image;
    struct sucrune_host_context host;
    void *stack_mapping, *signal_mapping;
    size_t stack_mapping_size, signal_mapping_size;
    uintptr_t stack_start, stack_end, stack_pointer, signal_start, signal_end;
    volatile sig_atomic_t trap_count, write_calls, exit_calls, exit_code;
    volatile sig_atomic_t entry_executed, on_alt_stack, output_size;
    unsigned char output[OUTPUT_CAPACITY];
    bool filter_installed, thread_joined, handler_restored, returned_to_host;
    int negative_tests;
};
static pthread_mutex_t elf_lock = PTHREAD_MUTEX_INITIALIZER;
static _Atomic(struct elf_state *) active_state;

static void fail(struct elf_state *state, const char *stage, const char *message, int error) {
    state->status = "failed";
    state->stage = stage;
    state->message = message;
    state->error_number = error;
}

static int contains(uintptr_t start, uintptr_t end, uintptr_t address, size_t size) {
    return address >= start && address <= end && size <= end - address;
}

/* Only the embedded trusted ELF is admitted. This bounded copy is output
 * collection, not a security boundary. No allocation, JNI, logging or lock
 * occurs inside the handler. Unrecognized guest calls return Linux ENOSYS. */
static void guest_sigsys(int number, siginfo_t *info, void *context) {
    struct elf_state *state = atomic_load_explicit(&active_state, memory_order_acquire);
    if (number != SIGSYS || info == NULL || context == NULL || state == NULL ||
        info->si_code != SYS_SECCOMP || info->si_errno != (int)ELF_TRAP_TAG ||
        info->si_arch != AUDIT_ARCH_AARCH64) {
        _exit(128 + SIGSYS);
    }
    ucontext_t *uc = (ucontext_t *)context;
    uintptr_t pc = (uintptr_t)uc->uc_mcontext.pc;
    if (!contains((uintptr_t)state->image.base,
                  (uintptr_t)state->image.base + state->image.size, pc, 0U)) {
        _exit(128 + SIGSYS);
    }
    unsigned char marker;
    if (!contains(state->signal_start, state->signal_end, (uintptr_t)&marker, 1U)) {
        _exit(128 + SIGSYS);
    }
    state->on_alt_stack = 1;
    state->entry_executed = 1;
    if (state->trap_count >= 64) _exit(128 + SIGSYS);
    state->trap_count++;
    if (info->si_syscall == 64) { // Linux/AArch64 write
        uint64_t fd = uc->uc_mcontext.regs[0];
        uintptr_t pointer = (uintptr_t)uc->uc_mcontext.regs[1];
        size_t count = (size_t)uc->uc_mcontext.regs[2];
        if (fd != 1U) {
            uc->uc_mcontext.regs[0] = (uint64_t)(int64_t)-EBADF;
            return;
        }
        size_t used = (size_t)state->output_size;
        if (count > OUTPUT_CAPACITY - 1U - used) {
            uc->uc_mcontext.regs[0] = (uint64_t)(int64_t)-EFBIG;
            return;
        }
        if (!sucrune_elf_readable(&state->image, pointer, count) &&
            !contains(state->stack_start, state->stack_end, pointer, count)) {
            uc->uc_mcontext.regs[0] = (uint64_t)(int64_t)-EFAULT;
            return;
        }
        const volatile unsigned char *source = (const volatile unsigned char *)pointer;
        for (size_t i = 0; i < count; i++) state->output[used + i] = source[i];
        state->output_size = (sig_atomic_t)(used + count);
        state->write_calls++;
        uc->uc_mcontext.regs[0] = (uint64_t)count;
    } else if (info->si_syscall == 93 || info->si_syscall == 94) { // exit / exit_group
        state->exit_code = (sig_atomic_t)(uc->uc_mcontext.regs[0] & 255U);
        state->exit_calls++;
        // Let rt_sigreturn unwind the signal frame before restoring host ABI.
        uc->uc_mcontext.regs[0] = (uint64_t)(uintptr_t)&state->host;
        uc->uc_mcontext.sp = state->host.sp;
        uc->uc_mcontext.pc = (uint64_t)(uintptr_t)&sucrune_guest_return;
    } else {
        uc->uc_mcontext.regs[0] = (uint64_t)(int64_t)-ENOSYS;
    }
}

static int install_filter(const struct sucrune_elf_image *image) {
    uintptr_t start = (uintptr_t)image->base;
    uintptr_t end = start + image->size;
    // The compact BPF range comparison below intentionally rejects a mapping
    // crossing a 4 GiB boundary instead of silently trapping the wrong range.
    if ((start >> 32U) != (end >> 32U)) { errno = ERANGE; return -1; }
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (unsigned int)offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (unsigned int)offsetof(struct seccomp_data, instruction_pointer) + 4U),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)(start >> 32U), 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (unsigned int)offsetof(struct seccomp_data, instruction_pointer)),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, (uint32_t)start, 0, 2),
        // seccomp reports the PC after svc, including one past the last byte.
        BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, (uint32_t)end, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP | ELF_TRAP_TAG),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = { .len = (unsigned short)(sizeof(code) / sizeof(code[0])), .filter = code };
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}

static int guarded_stack(size_t usable, size_t page, void **mapping, size_t *total,
                         uintptr_t *start, uintptr_t *end) {
    *total = usable + 2U * page;
    void *memory = mmap(NULL, *total, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) return -1;
    *mapping = memory;
    *start = (uintptr_t)memory + page;
    *end = *start + usable;
    return mprotect((void *)*start, usable, PROT_READ | PROT_WRITE);
}

static int initial_stack(struct elf_state *state) {
    if (guarded_stack(GUEST_STACK_SIZE, (size_t)state->page_size,
                      &state->stack_mapping, &state->stack_mapping_size,
                      &state->stack_start, &state->stack_end) != 0) return -1;
    uintptr_t cursor = state->stack_end;
    static const char argument[] = "sucrune-hello";
    static const char environment[] = "SUCRUNE=1";
    static const char platform[] = "aarch64";
    cursor -= sizeof(argument);
    memcpy((void *)cursor, argument, sizeof(argument));
    uintptr_t arg = cursor;
    cursor -= sizeof(environment);
    memcpy((void *)cursor, environment, sizeof(environment));
    uintptr_t env = cursor;
    cursor -= sizeof(platform);
    memcpy((void *)cursor, platform, sizeof(platform));
    uintptr_t arch = cursor;
    cursor = (cursor - 16U) & ~(uintptr_t)15U;
    uintptr_t random = cursor;
    long random_size = syscall(SYS_getrandom, (void *)random, 16U, 0U);
    if (random_size != 16) {
        if (random_size >= 0) errno = EIO;
        return -1;
    }
    uint64_t words[] = {
        1, arg, 0, env, 0,
        AT_PHDR, state->image.phdr, AT_PHENT, state->image.phentsize,
        AT_PHNUM, state->image.phnum, AT_PAGESZ, (uint64_t)state->page_size,
        AT_BASE, 0, AT_FLAGS, 0, AT_ENTRY, state->image.entry,
        AT_UID, (uint64_t)getuid(), AT_EUID, (uint64_t)geteuid(),
        AT_GID, (uint64_t)getgid(), AT_EGID, (uint64_t)getegid(),
        AT_SECURE, 0, AT_RANDOM, random, AT_EXECFN, arg, AT_PLATFORM, arch,
        AT_NULL, 0,
    };
    cursor = (cursor - sizeof(words)) & ~(uintptr_t)15U;
    memcpy((void *)cursor, words, sizeof(words));
    state->stack_pointer = cursor;
    return 0;
}

static void *run_guest(void *argument) {
    struct elf_state *state = (struct elf_state *)argument;
    if (guarded_stack(SIGNAL_STACK_SIZE, (size_t)state->page_size,
                      &state->signal_mapping, &state->signal_mapping_size,
                      &state->signal_start, &state->signal_end) != 0) {
        fail(state, "signal_stack", "Cannot allocate guarded signal stack.", errno);
        return NULL;
    }
    stack_t alt = { .ss_sp = (void *)state->signal_start, .ss_size = SIGNAL_STACK_SIZE, .ss_flags = 0 };
    if (sigaltstack(&alt, NULL) != 0) {
        fail(state, "signal_stack", "Cannot activate alternate signal stack.", errno);
        return NULL;
    }
    sigset_t signals;
    sigemptyset(&signals);
    sigaddset(&signals, SIGSYS);
    int error = pthread_sigmask(SIG_UNBLOCK, &signals, NULL);
    if (error != 0) { fail(state, "signal_mask", "Cannot unblock SIGSYS.", error); return NULL; }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) != 0) {
        fail(state, "no_new_privs", "Cannot enable no_new_privs.", errno);
        return NULL;
    }
    atomic_store_explicit(&active_state, state, memory_order_release);
    if (install_filter(&state->image) != 0) {
        fail(state, "seccomp_install", "Cannot install guest-range syscall filter.", errno);
        return NULL;
    }
    state->filter_installed = true;
    (void)sucrune_guest_enter(state->image.entry, state->stack_pointer, &state->host, 0);
    state->returned_to_host = true;
    static const char expected[] = "Hello from Sucrune ELF!\n";
    if (state->entry_executed != 1 || state->trap_count != 2 || state->exit_calls != 1 ||
        state->write_calls != 1 || state->exit_code != 42 || state->on_alt_stack != 1 ||
        state->output_size != (sig_atomic_t)(sizeof(expected) - 1U) ||
        memcmp(state->output, expected, sizeof(expected) - 1U) != 0) {
        fail(state, "guest_result", "The ELF did not produce its expected output and exit status.", 0);
    } else {
        state->status = "passed";
        state->stage = "complete";
        state->message = "The loaded Linux ELF checked its stack and BSS, wrote stdout, and exited with code 42.";
    }
    // The filter persists until this pthread exits. Mappings survive join.
    return NULL;
}

static void json_escape(const unsigned char *source, size_t size, char *destination, size_t capacity) {
    static const char hex[] = "0123456789abcdef";
    size_t used = 0;
    for (size_t i = 0; i < size && used + 6U < capacity; i++) {
        unsigned char c = source[i];
        if (c == '"' || c == '\\') { destination[used++] = '\\'; destination[used++] = (char)c; }
        else if (c < 32U || c >= 127U) {
            destination[used++] = '\\'; destination[used++] = 'u';
            destination[used++] = '0'; destination[used++] = '0';
            destination[used++] = hex[c >> 4U]; destination[used++] = hex[c & 15U];
        } else destination[used++] = (char)c;
    }
    destination[used] = '\0';
}

static void make_report(const struct elf_state *state, char *report, size_t capacity) {
    struct utsname system;
    memset(&system, 0, sizeof(system));
    if (uname(&system) != 0) (void)snprintf(system.release, sizeof(system.release), "unknown");
    char kernel[6U * sizeof(system.release) + 1U];
    char output[6U * OUTPUT_CAPACITY + 1U];
    json_escape((const unsigned char *)system.release, strlen(system.release), kernel, sizeof(kernel));
    json_escape(state->output, (size_t)state->output_size, output, sizeof(output));
    int count = snprintf(report, capacity,
        "{\"schema_version\":1,\"probe\":\"arm64_elf\",\"status\":\"%s\",\"stage\":\"%s\","
        "\"message\":\"%s\",\"error_number\":%d,"
        "\"host\":{\"abi\":\"arm64-v8a\",\"kernel\":\"%s\",\"page_size\":%ld,\"pid\":%ld,\"uid\":%ld},"
        "\"evidence\":{\"elf_machine\":183,\"elf_type\":3,\"entry_executed\":%s,"
        "\"stdout\":\"%s\",\"exit_code\":%d,\"write_calls\":%d,\"exit_calls\":%d,\"trap_count\":%d,"
        "\"guest_argc\":1,\"stack_alignment\":16,\"loaded_segments\":%zu,\"bss_zeroed\":%s,"
        "\"filter_installed\":%s,\"on_alt_stack\":%s,\"returned_to_host\":%s,"
        "\"thread_joined\":%s,\"handler_restored\":%s,\"validator_negative_tests\":%d}}",
        state->status, state->stage, state->message, state->error_number,
        kernel, state->page_size, (long)getpid(), (long)getuid(),
        state->entry_executed ? "true" : "false", output, (int)state->exit_code,
        (int)state->write_calls, (int)state->exit_calls, (int)state->trap_count,
        state->image.segment_count, state->exit_code == 42 ? "true" : "false",
        state->filter_installed ? "true" : "false", state->on_alt_stack ? "true" : "false",
        state->returned_to_host ? "true" : "false", state->thread_joined ? "true" : "false",
        state->handler_restored ? "true" : "false", state->negative_tests);
    if (count < 0 || (size_t)count >= capacity) {
        (void)snprintf(report, capacity, "{\"schema_version\":1,\"probe\":\"arm64_elf\",\"status\":\"failed\",\"stage\":\"report_buffer\"}");
    }
}

int sucrune_elf_probe_run(char *report, size_t capacity) {
    if (report == NULL || capacity == 0) return 1;
    if (pthread_mutex_trylock(&elf_lock) != 0) {
        (void)snprintf(report, capacity, "{\"schema_version\":1,\"probe\":\"arm64_elf\",\"status\":\"failed\",\"stage\":\"busy\"}");
        return 1;
    }
    struct elf_state state = { .status = "failed", .stage = "initializing",
        .message = "The ELF experiment has not completed.", .exit_code = -1 };
    state.page_size = sysconf(_SC_PAGESIZE);
    size_t elf_size = (size_t)((uintptr_t)sucrune_hello_end - (uintptr_t)sucrune_hello_start);
    state.negative_tests = sucrune_elf_selftest(sucrune_hello_start, elf_size);
    if (state.negative_tests == 0) {
        fail(&state, "elf_validator_selftest", "The fixture or a malformed ELF boundary check failed.", 0);
        goto cleanup;
    }
    enum sucrune_elf_error error = sucrune_elf_load(sucrune_hello_start, elf_size, &state.image);
    if (error != SUCRUNE_ELF_OK) {
        int saved_error = (error == SUCRUNE_ELF_MAP_FAILED || error == SUCRUNE_ELF_PROTECT_FAILED) ? errno : 0;
        fail(&state, "elf_load", sucrune_elf_error_message(error), saved_error);
        goto cleanup;
    }
    if (state.image.phdr == 0) {
        fail(&state, "initial_stack", "The fixture program headers are not mapped.", 0);
        goto cleanup;
    }
    if (initial_stack(&state) != 0) {
        fail(&state, "initial_stack", "Cannot establish the Linux initial stack and mapped program headers.", errno);
        goto cleanup;
    }
    struct sigaction action, previous;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = guest_sigsys;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGSYS, &action, &previous) != 0) {
        fail(&state, "signal_handler", "Cannot install the guest SIGSYS handler.", errno);
        goto cleanup;
    }
    pthread_t worker;
    int thread_error = pthread_create(&worker, NULL, run_guest, &state);
    if (thread_error != 0) fail(&state, "thread_create", "Cannot create the guest worker.", thread_error);
    else {
        if (pthread_join(worker, NULL) != 0) _exit(120);
        state.thread_joined = true;
    }
    atomic_store_explicit(&active_state, NULL, memory_order_release);
    if (sigaction(SIGSYS, &previous, NULL) != 0) fail(&state, "handler_restore", "Cannot restore SIGSYS handler.", errno);
    else state.handler_restored = true;
cleanup:
    if (state.stack_mapping != NULL && munmap(state.stack_mapping, state.stack_mapping_size) != 0)
        fail(&state, "stack_release", "Cannot release guest stack.", errno);
    if (state.signal_mapping != NULL && munmap(state.signal_mapping, state.signal_mapping_size) != 0)
        fail(&state, "signal_stack_release", "Cannot release signal stack.", errno);
    // Report mapped segment evidence before unload clears the image structure.
    make_report(&state, report, capacity);
    sucrune_elf_unload(&state.image);
    int result = strcmp(state.status, "passed") == 0 ? 0 : 1;
    (void)pthread_mutex_unlock(&elf_lock);
    return result;
}
#else
int sucrune_elf_probe_run(char *report, size_t capacity) {
    if (report != NULL && capacity != 0) {
        (void)snprintf(report, capacity,
            "{\"schema_version\":1,\"probe\":\"arm64_elf\",\"status\":\"unsupported\","
            "\"stage\":\"architecture\",\"message\":\"The ELF execution experiment requires native ARM64.\","
            "\"host\":{\"abi\":\"x86_64\",\"page_size\":%ld,\"pid\":%ld,\"uid\":%ld}}",
            sysconf(_SC_PAGESIZE), (long)getpid(), (long)getuid());
    }
    return 1;
}
#endif
