#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

static volatile sig_atomic_t first, second, invalid, edit_frame;
static void nested(int number) { if (number != SIGUSR2) invalid = 1; second++; }
static void handled(int number, siginfo_t *info, void *context) {
    if (number != SIGUSR1 || info == NULL || info->si_signo != SIGUSR1 || info->si_pid != getpid()) invalid = 2;
    first++;
    if (raise(SIGUSR2) != 0) invalid = 3;
    if (edit_frame) {
        ucontext_t *uc = context;
        uc->uc_mcontext.regs[0] = 123;
        /* The Linux ARM64 FPSIMD record begins in the aligned reserved area;
         * q0 is 16 bytes after its header/FPSR/FPCR fields. */
        unsigned char *record = (unsigned char *)uc->uc_mcontext.__reserved;
        uint32_t magic; memcpy(&magic, record, sizeof(magic));
        if (magic != UINT32_C(0x46508001)) invalid = 4;
        const uint64_t vector = UINT64_C(0x1122334455667788);
        memcpy(record + 16, &vector, sizeof(vector));
    }
}
int main(void) {
    struct sigaction action = {0}, other = {0}, before = {0};
    action.sa_sigaction = handled; action.sa_flags = SA_SIGINFO;
    other.sa_handler = nested;
    if (sigaction(SIGUSR1, &action, NULL) != 0 || sigaction(SIGUSR2, &other, NULL) != 0) return 10;
    sigset_t mask; sigemptyset(&mask); sigaddset(&mask, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) != 0 || raise(SIGUSR1) != 0 || first != 0) return 11;
    if (sigprocmask(SIG_UNBLOCK, &mask, NULL) != 0 || first != 1 || second != 1 || invalid) return 12;
    edit_frame = 1;
    register long x0 __asm__("x0") = syscall(SYS_gettid);
    register long x1 __asm__("x1") = SIGUSR1;
    register long x8 __asm__("x8") = SYS_tkill;
    uint64_t vector;
    __asm__ volatile("movi v0.16b, #0x5a\n\tsvc #0\n\tumov %1, v0.d[0]"
        : "+r"(x0), "=r"(vector) : "r"(x1), "r"(x8) : "memory", "cc", "v0");
    if (x0 != 123 || vector != UINT64_C(0x1122334455667788) || first != 2 || second != 2 || invalid) return 13;
    edit_frame = 0;
    action.sa_flags = SA_SIGINFO | SA_RESETHAND;
    if (sigaction(SIGUSR1, &action, NULL) != 0 || raise(SIGUSR1) != 0 || first != 3 || second != 3) return 14;
    if (sigaction(SIGUSR1, NULL, &before) != 0 || before.sa_handler != SIG_DFL) return 15;
    puts("LINUX_SIGNAL_OK blocked nested siginfo gpr fpsimd reset");
    return invalid ? 16 : 0;
}
