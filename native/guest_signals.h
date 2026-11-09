#ifndef SUCRUNE_GUEST_SIGNALS_H
#define SUCRUNE_GUEST_SIGNALS_H

#include <stddef.h>
#include <stdint.h>

/* Linux AArch64 ABI, independent of the host libc and its signal structures.
 * This first profile delivers self-directed standard signals at syscall
 * boundaries. It does not implement host asynchronous signals, realtime
 * queues or job-control stops. All calls are serialized
 * by the owning guest thread; sharing a process table across threads requires
 * an external lock/dispatcher. No function calls a guest callback in host C. */
#define SUCRUNE_SIGNAL_COUNT 64U
#define SUCRUNE_SIGNAL_DEPTH 8U
#define SUCRUNE_SIGNAL_SA_SIGINFO UINT64_C(0x00000004)
#define SUCRUNE_SIGNAL_SA_RESTORER UINT64_C(0x04000000)
#define SUCRUNE_SIGNAL_SA_ONSTACK UINT64_C(0x08000000)
#define SUCRUNE_SIGNAL_SA_RESTART UINT64_C(0x10000000)
#define SUCRUNE_SIGNAL_SA_NODEFER UINT64_C(0x40000000)
#define SUCRUNE_SIGNAL_SA_RESETHAND UINT64_C(0x80000000)
#define SUCRUNE_SIGNAL_FPSIMD_MAGIC UINT32_C(0x46508001)
#define SUCRUNE_SIGNAL_NZCV UINT64_C(0xf0000000)
#define SUCRUNE_SS_ONSTACK 1
#define SUCRUNE_SS_DISABLE 2
#define SUCRUNE_SS_AUTODISARM UINT32_C(0x80000000)
#define SUCRUNE_MINSIGSTKSZ 5120U /* Linux AArch64 UAPI */

struct sucrune_signal_action { uint64_t handler, flags, restorer, mask; };
struct sucrune_signal_cpu {
    uint64_t regs[31], sp, pc, pstate;
    uint32_t fpsr, fpcr;
    uint64_t vectors[64]; /* q0.low, q0.high, ..., q31.high */
};
struct sucrune_signal_info {
    int32_t signo, error, code, padding;
    int32_t pid;
    uint32_t uid;
    unsigned char payload[104];
};
struct sucrune_signal_stack { uint64_t sp; int32_t flags; uint32_t padding; uint64_t size; };
struct sucrune_signal_context {
    uint64_t fault_address, regs[31], sp, pc, pstate;
    uint64_t alignment_padding;
    _Alignas(16) unsigned char reserved[4096];
};
struct sucrune_signal_ucontext {
    uint64_t flags, link;
    struct sucrune_signal_stack stack;
    uint64_t mask;
    unsigned char mask_padding[120];
    uint64_t alignment_padding;
    struct sucrune_signal_context machine;
};
struct sucrune_signal_frame {
    struct sucrune_signal_info info;
    struct sucrune_signal_ucontext context;
};
struct sucrune_signal_fpsimd {
    uint32_t magic, size, fpsr, fpcr;
    uint64_t vectors[64];
};
struct sucrune_signal_process { struct sucrune_signal_action actions[65]; };
struct sucrune_signal_thread {
    int64_t pid, tid;
    uint32_t uid, depth;
    uint64_t mask, pending;
    struct sucrune_signal_stack altstack;
    struct sucrune_signal_info pending_info[65];
    uintptr_t frames[SUCRUNE_SIGNAL_DEPTH];
};
struct sucrune_signal_memory {
    void *opaque;
    /* Return nonzero only for currently mapped guest memory / guest RX code.
     * The mapped addresses are native addresses; the module copies only after
     * successful validation. The caller prevents concurrent map changes. */
    int (*access)(void *opaque, uintptr_t address, size_t size, int write_access);
    int (*executable)(void *opaque, uintptr_t address);
    uintptr_t restorer; /* Trusted trampoline mapped RX inside guest ranges. */
};
enum sucrune_signal_delivery {
    SUCRUNE_SIGNAL_NONE = 0,
    SUCRUNE_SIGNAL_ENTERED = 1,
    SUCRUNE_SIGNAL_TERMINATE = 2
};

void sucrune_signals_init(struct sucrune_signal_process *process,
                          struct sucrune_signal_thread *thread,
                          int64_t pid, int64_t tid, uint32_t uid);
int sucrune_signals_action(struct sucrune_signal_process *process,
                           const struct sucrune_signal_memory *memory,
                           uint64_t number, uintptr_t action, uintptr_t old_action,
                           uint64_t sigset_size);
int sucrune_signals_altstack(struct sucrune_signal_stack *current,
                             const struct sucrune_signal_memory *memory,
                             uintptr_t guest_sp, uintptr_t set, uintptr_t old_set);
int sucrune_signals_mask(struct sucrune_signal_thread *thread,
                         const struct sucrune_signal_memory *memory,
                         uint64_t how, uintptr_t set, uintptr_t old_set,
                         uint64_t sigset_size);
/* operation: ARM64 kill=129, tkill=130, tgkill=131; a0..a2 retain syscall
 * argument order. Other positive process/thread IDs return ESRCH. Process
 * group broadcasts, realtime queues and default stop actions are unsupported. */
int sucrune_signals_self(struct sucrune_signal_process *process,
                         struct sucrune_signal_thread *thread,
                         unsigned int operation, int64_t a0, int64_t a1, int64_t a2);
/* Called only after a syscall result has been written to cpu->regs[0]. On
 * ENTERED, leave the host SIGSYS handler normally so the kernel restores the
 * new guest PC/SP. Never invoke the handler while SIGSYS is still blocked.
 * TERMINATE sets *termination_signal for the caller's normal exit path. */
int sucrune_signals_deliver(struct sucrune_signal_process *process,
                            struct sucrune_signal_thread *thread,
                            const struct sucrune_signal_memory *memory,
                            struct sucrune_signal_cpu *cpu, int *termination_signal);
/* Implements guest rt_sigreturn=139. Success restores cpu including x0;
 * caller must not overwrite x0 with this function's return value. Malformed
 * frames return negative errno without changing CPU, mask or frame depth. */
int sucrune_signals_return(struct sucrune_signal_thread *thread,
                           const struct sucrune_signal_memory *memory,
                           struct sucrune_signal_cpu *cpu);

_Static_assert(sizeof(struct sucrune_signal_action) == 32U, "ARM64 kernel sigaction");
_Static_assert(sizeof(struct sucrune_signal_info) == 128U, "Linux siginfo size");
_Static_assert(offsetof(struct sucrune_signal_info, pid) == 16U, "Linux siginfo union");
_Static_assert(sizeof(struct sucrune_signal_stack) == 24U, "ARM64 stack_t");
_Static_assert(offsetof(struct sucrune_signal_context, reserved) == 288U, "ARM64 reserved offset");
_Static_assert(sizeof(struct sucrune_signal_context) == 4384U, "ARM64 sigcontext size");
_Static_assert(offsetof(struct sucrune_signal_ucontext, machine) == 176U, "ARM64 mcontext offset");
_Static_assert(sizeof(struct sucrune_signal_ucontext) == 4560U, "ARM64 ucontext size");
_Static_assert(sizeof(struct sucrune_signal_frame) == 4688U, "ARM64 rt_sigframe size");
_Static_assert(sizeof(struct sucrune_signal_fpsimd) == 528U, "ARM64 FPSIMD record size");
#endif
