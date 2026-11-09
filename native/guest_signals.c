#include "guest_signals.h"
#include <errno.h>
#include <string.h>

#define SIGNAL_KILL 9U
#define SIGNAL_STOP 19U
#define SIGNAL_UNBLOCKABLE ((UINT64_C(1) << (SIGNAL_KILL - 1U)) | (UINT64_C(1) << (SIGNAL_STOP - 1U)))
#define ACTION_FLAGS UINT64_C(0xdc000007)
#define HANDLER_FLAGS (SUCRUNE_SIGNAL_SA_SIGINFO | SUCRUNE_SIGNAL_SA_RESTORER | SUCRUNE_SIGNAL_SA_RESTART | SUCRUNE_SIGNAL_SA_NODEFER | SUCRUNE_SIGNAL_SA_RESETHAND | SUCRUNE_SIGNAL_SA_ONSTACK)

static uint64_t signal_bit(unsigned int number) { return UINT64_C(1) << (number - 1U); }
static int accessible(const struct sucrune_signal_memory *memory, uintptr_t address, size_t length, int write_access) {
    return memory != NULL && memory->access != NULL && address != 0U &&
        length <= UINTPTR_MAX - address && memory->access(memory->opaque, address, length, write_access);
}
static int executable(const struct sucrune_signal_memory *memory, uintptr_t address) {
    return memory != NULL && memory->executable != NULL && address != 0U && (address & 3U) == 0U &&
        memory->executable(memory->opaque, address);
}
static int ignored_default(unsigned int number) { return number == 17U || number == 18U || number == 23U || number == 28U; }
static int stopped_default(unsigned int number) { return number == 19U || number == 20U || number == 21U || number == 22U; }

static int on_altstack(const struct sucrune_signal_stack *stack, uint64_t sp) {
    return sp > stack->sp && sp - stack->sp <= stack->size &&
        ((uint32_t)stack->flags & SUCRUNE_SS_AUTODISARM) == 0U;
}

static int configure_altstack(struct sucrune_signal_stack *current, uint64_t sp,
                              const struct sucrune_signal_stack *requested) {
    if (on_altstack(current, sp)) return -EPERM;
    uint32_t mode = (uint32_t)requested->flags & ~SUCRUNE_SS_AUTODISARM;
    if (mode != 0U && mode != SUCRUNE_SS_ONSTACK && mode != SUCRUNE_SS_DISABLE) return -EINVAL;
    struct sucrune_signal_stack stack = {.flags = requested->flags};
    if (mode != SUCRUNE_SS_DISABLE) {
        if (requested->size < SUCRUNE_MINSIGSTKSZ) return -ENOMEM;
        if (requested->sp > UINTPTR_MAX || requested->size > UINTPTR_MAX - requested->sp) return -EFAULT;
        stack.sp = requested->sp;
        stack.size = requested->size;
    }
    *current = stack;
    return 0;
}

int sucrune_signals_altstack(struct sucrune_signal_stack *current, const struct sucrune_signal_memory *memory,
                             uintptr_t guest_sp, uintptr_t set, uintptr_t old_set) {
    if (current == NULL) return -EINVAL;
    if ((set != 0U && !accessible(memory, set, sizeof(*current), 0)) ||
        (old_set != 0U && !accessible(memory, old_set, sizeof(*current), 1))) return -EFAULT;
    struct sucrune_signal_stack old = *current;
    uint32_t mode = old.size == 0U ? SUCRUNE_SS_DISABLE : (uint32_t)on_altstack(current, guest_sp);
    old.flags = (int32_t)(mode | ((uint32_t)old.flags & SUCRUNE_SS_AUTODISARM));
    if (set != 0U) {
        struct sucrune_signal_stack requested;
        memcpy(&requested, (const void *)set, sizeof(requested));
        int result = configure_altstack(current, guest_sp, &requested);
        if (result != 0) return result;
    }
    if (old_set != 0U) memcpy((void *)old_set, &old, sizeof(old));
    return 0;
}

void sucrune_signals_init(struct sucrune_signal_process *process, struct sucrune_signal_thread *thread,
                          int64_t pid, int64_t tid, uint32_t uid) {
    memset(process, 0, sizeof(*process)); memset(thread, 0, sizeof(*thread));
    thread->pid = pid; thread->tid = tid; thread->uid = uid;
}

int sucrune_signals_action(struct sucrune_signal_process *process, const struct sucrune_signal_memory *memory,
                           uint64_t number, uintptr_t action, uintptr_t old_action, uint64_t sigset_size) {
    if (process == NULL || number == 0U || number > SUCRUNE_SIGNAL_COUNT || sigset_size != 8U ||
        (action != 0U && (number == SIGNAL_KILL || number == SIGNAL_STOP))) return -EINVAL;
    if ((action != 0U && !accessible(memory, action, sizeof(struct sucrune_signal_action), 0)) ||
        (old_action != 0U && !accessible(memory, old_action, sizeof(struct sucrune_signal_action), 1))) return -EFAULT;
    struct sucrune_signal_action next = {0};
    if (action != 0U) {
        memcpy(&next, (const void *)action, sizeof(next));
        /* Linux ignores unknown sa_flags. Capability flags that promise
         * behavior not implemented by this profile fail explicitly. */
        next.flags &= ACTION_FLAGS;
        if (next.handler > 1U && (next.flags & ~HANDLER_FLAGS) != 0U) return -ENOTSUP;
        next.mask &= ~SIGNAL_UNBLOCKABLE;
    }
    /* Read next first: new and old pointers are allowed to alias. */
    if (old_action != 0U) memcpy((void *)old_action, &process->actions[number], sizeof(next));
    if (action != 0U) {
        process->actions[number] = next;
        /* Pending ignored signals are discarded by the delivery pass; table
         * updates do not own or traverse other thread state. */
    }
    return 0;
}

int sucrune_signals_mask(struct sucrune_signal_thread *thread, const struct sucrune_signal_memory *memory,
                         uint64_t how, uintptr_t set, uintptr_t old_set, uint64_t sigset_size) {
    if (thread == NULL || sigset_size != 8U || (set != 0U && how > 2U)) return -EINVAL;
    if ((set != 0U && !accessible(memory, set, 8U, 0)) || (old_set != 0U && !accessible(memory, old_set, 8U, 1))) return -EFAULT;
    uint64_t next = 0U, before = thread->mask;
    if (set != 0U) memcpy(&next, (const void *)set, sizeof(next));
    if (old_set != 0U) memcpy((void *)old_set, &before, sizeof(before));
    if (set != 0U) {
        if (how == 0U) thread->mask |= next;
        else if (how == 1U) thread->mask &= ~next;
        else thread->mask = next;
        thread->mask &= ~SIGNAL_UNBLOCKABLE;
    }
    return 0;
}

int sucrune_signals_self(struct sucrune_signal_process *process, struct sucrune_signal_thread *thread,
                         unsigned int operation, int64_t a0, int64_t a1, int64_t a2) {
    if (process == NULL || thread == NULL) return -EINVAL;
    int64_t number;
    int32_t code;
    if (operation == 129U) {
        number = a1; code = 0; /* SI_USER */
        if (a0 <= 0) return -ENOTSUP;
        if (a0 != thread->pid) return -ESRCH;
    } else if (operation == 130U) {
        number = a1; code = -6; /* SI_TKILL */
        if (a0 <= 0) return -EINVAL;
        if (a0 != thread->tid) return -ESRCH;
    } else if (operation == 131U) {
        number = a2; code = -6;
        if (a0 <= 0 || a1 <= 0) return -EINVAL;
        if (a0 != thread->pid || a1 != thread->tid) return -ESRCH;
    } else return -ENOSYS;
    if (number < 0 || number > (int64_t)SUCRUNE_SIGNAL_COUNT) return -EINVAL;
    if (number == 0) return 0;
    /* Standard signals coalesce. Realtime signals need an ordered queue, so
     * do not silently apply standard-signal semantics to them. */
    if (number > 31) return -ENOTSUP;
    unsigned int signo = (unsigned int)number;
    const struct sucrune_signal_action *action = &process->actions[signo];
    if (action->handler == 1U || (action->handler == 0U && ignored_default(signo))) return 0;
    if (action->handler == 0U && stopped_default(signo)) return -ENOTSUP;
    uint64_t bit = signal_bit(signo);
    if ((thread->pending & bit) == 0U) {
        struct sucrune_signal_info info = {0};
        info.signo = (int32_t)signo; info.code = code; info.pid = (int32_t)thread->pid; info.uid = thread->uid;
        thread->pending_info[signo] = info;
        thread->pending |= bit;
    }
    return 0;
}

static void save_cpu(struct sucrune_signal_frame *frame, const struct sucrune_signal_cpu *cpu, uint64_t mask) {
    frame->context.mask = mask;
    memcpy(frame->context.machine.regs, cpu->regs, sizeof(cpu->regs));
    frame->context.machine.sp = cpu->sp; frame->context.machine.pc = cpu->pc;
    frame->context.machine.pstate = cpu->pstate & SUCRUNE_SIGNAL_NZCV;
    struct sucrune_signal_fpsimd fpsimd = { .magic = SUCRUNE_SIGNAL_FPSIMD_MAGIC, .size = sizeof(fpsimd),
        .fpsr = cpu->fpsr, .fpcr = cpu->fpcr };
    memcpy(fpsimd.vectors, cpu->vectors, sizeof(cpu->vectors));
    memcpy(frame->context.machine.reserved, &fpsimd, sizeof(fpsimd));
    /* The zero-initialized remainder contains the mandatory null terminator.
     * No native uc_stack, extra_context pointer, TLS or host state is exposed. */
}

int sucrune_signals_deliver(struct sucrune_signal_process *process, struct sucrune_signal_thread *thread,
                            const struct sucrune_signal_memory *memory, struct sucrune_signal_cpu *cpu,
                            int *termination_signal) {
    if (process == NULL || thread == NULL || cpu == NULL || termination_signal == NULL) return -EINVAL;
    *termination_signal = 0;
    /* Discard ignored pending signals even if their guest mask blocks them. */
    for (unsigned int number = 1U; number <= SUCRUNE_SIGNAL_COUNT; number++) {
        const struct sucrune_signal_action *action = &process->actions[number];
        if (action->handler == 1U || (action->handler == 0U && ignored_default(number))) thread->pending &= ~signal_bit(number);
    }
    uint64_t ready = thread->pending & ~thread->mask;
    if (ready == 0U) return SUCRUNE_SIGNAL_NONE;
    unsigned int number = 1U;
    while ((ready & signal_bit(number)) == 0U) number++;
    struct sucrune_signal_action action = process->actions[number];
    if (action.handler == 0U) {
        if (stopped_default(number)) return -ENOTSUP;
        thread->pending &= ~signal_bit(number);
        *termination_signal = (int)number;
        return SUCRUNE_SIGNAL_TERMINATE;
    }
    if (thread->depth >= SUCRUNE_SIGNAL_DEPTH) return -EOVERFLOW;
    uintptr_t restorer = (action.flags & SUCRUNE_SIGNAL_SA_RESTORER) != 0U ? (uintptr_t)action.restorer : memory == NULL ? 0U : memory->restorer;
    if (!executable(memory, (uintptr_t)action.handler) || !executable(memory, restorer) ||
        !executable(memory, (uintptr_t)cpu->pc)) return -EFAULT;
    const size_t total = sizeof(struct sucrune_signal_frame) + 2U * sizeof(uint64_t);
    int on_alt = on_altstack(&thread->altstack, cpu->sp);
    int switch_stack = (action.flags & SUCRUNE_SIGNAL_SA_ONSTACK) != 0U && thread->altstack.size != 0U && !on_alt;
    uint64_t top = switch_stack ? thread->altstack.sp + thread->altstack.size : cpu->sp;
    top &= ~UINT64_C(15);
    if (top < total || top > UINTPTR_MAX) return -EFAULT;
    uintptr_t address = (uintptr_t)top - total;
    /* The mapping enclosing the alternate stack may be larger than ss_size. */
    if (((switch_stack || on_alt) && address <= thread->altstack.sp) || !accessible(memory, address, total, 1)) return -EFAULT;
    struct sucrune_signal_frame frame;
    memset(&frame, 0, sizeof(frame));
    frame.info = thread->pending_info[number];
    frame.context.stack = thread->altstack;
    if (frame.context.stack.size == 0U) frame.context.stack.flags |= SUCRUNE_SS_DISABLE;
    save_cpu(&frame, cpu, thread->mask);
    uint64_t frame_record[2] = {cpu->regs[29], cpu->regs[30]};
    memcpy((void *)address, &frame, sizeof(frame));
    memcpy((void *)(address + sizeof(frame)), frame_record, sizeof(frame_record));
    if (((uint32_t)thread->altstack.flags & SUCRUNE_SS_AUTODISARM) != 0U)
        thread->altstack = (struct sucrune_signal_stack){0};
    thread->frames[thread->depth++] = address;
    thread->pending &= ~signal_bit(number);
    thread->mask |= action.mask;
    if ((action.flags & SUCRUNE_SIGNAL_SA_NODEFER) == 0U) thread->mask |= signal_bit(number);
    thread->mask &= ~SIGNAL_UNBLOCKABLE;
    if ((action.flags & SUCRUNE_SIGNAL_SA_RESETHAND) != 0U) process->actions[number].handler = 0U;
    cpu->regs[0] = number;
    if ((action.flags & SUCRUNE_SIGNAL_SA_SIGINFO) != 0U) {
        cpu->regs[1] = address + offsetof(struct sucrune_signal_frame, info);
        cpu->regs[2] = address + offsetof(struct sucrune_signal_frame, context);
    }
    cpu->regs[29] = address + sizeof(frame); cpu->regs[30] = restorer;
    cpu->sp = address; cpu->pc = action.handler;
    cpu->pstate &= SUCRUNE_SIGNAL_NZCV;
    return SUCRUNE_SIGNAL_ENTERED;
}

int sucrune_signals_return(struct sucrune_signal_thread *thread, const struct sucrune_signal_memory *memory,
                           struct sucrune_signal_cpu *cpu) {
    if (thread == NULL || cpu == NULL || thread->depth == 0U) return -EINVAL;
    if (cpu->sp > UINTPTR_MAX || (cpu->sp & 15U) != 0U ||
        cpu->sp != thread->frames[thread->depth - 1U]) return -EINVAL;
    uintptr_t address = (uintptr_t)cpu->sp;
    if (!accessible(memory, address, sizeof(struct sucrune_signal_frame), 0)) return -EFAULT;
    struct sucrune_signal_frame frame;
    memcpy(&frame, (const void *)address, sizeof(frame));
    const struct sucrune_signal_context *saved = &frame.context.machine;
    if ((saved->pstate & ~SUCRUNE_SIGNAL_NZCV) != 0U || saved->sp > UINTPTR_MAX ||
        saved->sp < 16U || (saved->sp & 15U) != 0U || !executable(memory, (uintptr_t)saved->pc) ||
        !accessible(memory, (uintptr_t)saved->sp - 16U, 16U, 1)) return -EFAULT;
    struct sucrune_signal_fpsimd fpsimd;
    memcpy(&fpsimd, saved->reserved, sizeof(fpsimd));
    if (fpsimd.magic != SUCRUNE_SIGNAL_FPSIMD_MAGIC || fpsimd.size != sizeof(fpsimd)) return -EINVAL;
    /* This profile publishes only FPSIMD. Reject extra_context, SVE/SME and
     * every unknown record rather than interpreting guest-provided host
     * pointers. Also require the emitted null-terminated tail to remain zero. */
    for (size_t i = sizeof(fpsimd); i < sizeof(saved->reserved); i++) if (saved->reserved[i] != 0U) return -EINVAL;
    struct sucrune_signal_cpu restored = {0};
    memcpy(restored.regs, saved->regs, sizeof(restored.regs));
    restored.sp = saved->sp; restored.pc = saved->pc; restored.pstate = saved->pstate;
    restored.fpsr = fpsimd.fpsr; restored.fpcr = fpsimd.fpcr;
    memcpy(restored.vectors, fpsimd.vectors, sizeof(restored.vectors));
    /* Linux restore_altstack ignores configuration errors, including EPERM
     * when a nested handler returns to its caller on the same stack. */
    (void)configure_altstack(&thread->altstack, restored.sp, &frame.context.stack);
    thread->mask = frame.context.mask & ~SIGNAL_UNBLOCKABLE;
    thread->frames[--thread->depth] = 0U;
    *cpu = restored;
    return 0;
}
