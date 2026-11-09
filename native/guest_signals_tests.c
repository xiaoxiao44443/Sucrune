#include "guest_signals.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expression) do { if (!(expression)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expression); abort(); } } while (0)
static _Alignas(16) unsigned char arena[131072];
static struct sucrune_signal_process process;
static struct sucrune_signal_thread thread;
static struct sucrune_signal_cpu cpu;
static unsigned int cases;
static uintptr_t base(void) { return (uintptr_t)arena; }
static uintptr_t data(void) { return base() + 4096U; }
static int access_memory(void *opaque, uintptr_t address, size_t size, int write_access) {
    (void)opaque;
    if (address < base() || address - base() > sizeof(arena) || size > sizeof(arena) - (address - base())) return 0;
    return !write_access || address >= data();
}
static int code_memory(void *opaque, uintptr_t address) {
    (void)opaque; return address >= base() && address < data();
}
static struct sucrune_signal_memory memory;
static uint64_t bit(unsigned int number) { return UINT64_C(1) << (number - 1U); }
static void reset(void) {
    memset(arena, 0xa5, sizeof(arena));
    sucrune_signals_init(&process, &thread, 71, 72, 10001U);
    memset(&cpu, 0, sizeof(cpu));
    for (size_t i = 0U; i < 31U; i++) cpu.regs[i] = UINT64_C(0x1020304050607080) + i;
    cpu.sp = base() + sizeof(arena); cpu.pc = base() + 768U; cpu.pstate = UINT64_C(0xa0000000);
    cpu.fpsr = 0x10U; cpu.fpcr = 0x400000U;
    for (size_t i = 0U; i < 64U; i++) cpu.vectors[i] = UINT64_C(0xdead000000000000) + i;
    memory.opaque = NULL; memory.access = access_memory; memory.executable = code_memory; memory.restorer = base() + 256U;
}
static int install(unsigned int number, uint64_t handler, uint64_t flags, uint64_t mask) {
    struct sucrune_signal_action action = {handler, flags, 0U, mask};
    memcpy((void *)data(), &action, sizeof(action));
    return sucrune_signals_action(&process, &memory, number, data(), 0U, 8U);
}
static void raise_signal(unsigned int number) {
    CHECK(sucrune_signals_self(&process, &thread, 131U, thread.pid, thread.tid, number) == 0);
}
static void enter(unsigned int number) {
    int termination = -1;
    raise_signal(number);
    CHECK(sucrune_signals_deliver(&process, &thread, &memory, &cpu, &termination) == SUCRUNE_SIGNAL_ENTERED);
    CHECK(termination == 0 && cpu.regs[0] == number);
}
static void actions_and_mask(void) {
    reset();
    CHECK(sucrune_signals_action(&process, &memory, 2U, 0U, data(), 8U) == 0);
    struct sucrune_signal_action action;
    memcpy(&action, (const void *)data(), sizeof(action));
    CHECK(action.handler == 0U && action.flags == 0U && action.mask == 0U);
    CHECK(install(2U, base() + 512U, SUCRUNE_SIGNAL_SA_ONSTACK, 0U) == 0);
    CHECK(process.actions[2].flags == SUCRUNE_SIGNAL_SA_ONSTACK);
    CHECK(install(2U, base() + 512U, SUCRUNE_SIGNAL_SA_RESETHAND, UINT64_MAX) == 0);
    CHECK((process.actions[2].mask & (bit(9) | bit(19))) == 0U);
    action = (struct sucrune_signal_action){1U, 0U, 0U, 0U};
    memcpy((void *)data(), &action, sizeof(action));
    CHECK(sucrune_signals_action(&process, &memory, 2U, data(), data(), 8U) == 0);
    memcpy(&action, (const void *)data(), sizeof(action));
    CHECK(action.handler == base() + 512U && process.actions[2].handler == 1U);
    CHECK(sucrune_signals_action(&process, &memory, 9U, data(), 0U, 8U) == -EINVAL);
    CHECK(sucrune_signals_action(&process, &memory, 65U, 0U, 0U, 8U) == -EINVAL);
    CHECK(sucrune_signals_action(&process, &memory, 2U, data(), 0U, 128U) == -EINVAL);
    CHECK(sucrune_signals_action(&process, &memory, 2U, data(), base(), 8U) == -EFAULT);
    CHECK(process.actions[2].handler == 1U);
    uint64_t mask = UINT64_MAX;
    memcpy((void *)data(), &mask, sizeof(mask));
    CHECK(sucrune_signals_mask(&thread, &memory, 2U, data(), data(), 8U) == 0);
    memcpy(&mask, (const void *)data(), sizeof(mask));
    CHECK(mask == 0U && thread.mask == (UINT64_MAX & ~(bit(9) | bit(19))));
    CHECK(sucrune_signals_mask(&thread, &memory, 999U, 0U, data(), 8U) == 0); /* ignored how for query */
    CHECK(sucrune_signals_mask(&thread, &memory, 999U, data(), 0U, 8U) == -EINVAL);
    cases++;
}
static void frame_and_roundtrip(void) {
    reset();
    struct sucrune_signal_cpu original = cpu;
    CHECK(install(10U, base() + 512U, SUCRUNE_SIGNAL_SA_SIGINFO, bit(12)) == 0);
    enter(10U);
    CHECK(thread.depth == 1U && (cpu.sp & 15U) == 0U && cpu.pc == base() + 512U && cpu.regs[30] == memory.restorer);
    CHECK(cpu.regs[1] == cpu.sp && cpu.regs[2] == cpu.sp + 128U);
    CHECK(thread.mask == (bit(10) | bit(12)));
    const struct sucrune_signal_frame *frame = (const void *)(uintptr_t)cpu.sp;
    CHECK(frame->info.signo == 10 && frame->info.code == -6 && frame->info.pid == 71 && frame->info.uid == 10001U);
    CHECK(frame->info.error == 0 && frame->info.padding == 0);
    for (size_t i = 0U; i < sizeof(frame->info.payload); i++) CHECK(frame->info.payload[i] == 0U);
    CHECK(frame->context.flags == 0U && frame->context.link == 0U && frame->context.stack.sp == 0U && frame->context.stack.flags == 2);
    CHECK(frame->context.machine.fault_address == 0U);
    for (size_t i = sizeof(struct sucrune_signal_fpsimd); i < sizeof(frame->context.machine.reserved); i++) CHECK(frame->context.machine.reserved[i] == 0U);
    cpu.regs[0] = 999U; cpu.regs[18] = 555U; cpu.vectors[63] = 123U;
    CHECK(sucrune_signals_return(&thread, &memory, &cpu) == 0);
    CHECK(memcmp(&cpu, &original, sizeof(cpu)) == 0 && thread.depth == 0U && thread.mask == 0U);
    CHECK(sucrune_signals_return(&thread, &memory, &cpu) == -EINVAL);
    cases++;
}
static void masking_coalescing_and_dispositions(void) {
    reset();
    CHECK(install(10U, base() + 512U, 0U, 0U) == 0);
    thread.mask = bit(10);
    CHECK(sucrune_signals_self(&process, &thread, 129U, 71, 10, 0) == 0);
    raise_signal(10U); /* original SI_USER information survives coalescing */
    int termination = -1;
    CHECK(sucrune_signals_deliver(&process, &thread, &memory, &cpu, &termination) == SUCRUNE_SIGNAL_NONE);
    CHECK(thread.pending == bit(10));
    thread.mask = 0U;
    CHECK(sucrune_signals_deliver(&process, &thread, &memory, &cpu, &termination) == SUCRUNE_SIGNAL_ENTERED);
    CHECK(((struct sucrune_signal_frame *)(uintptr_t)cpu.sp)->info.code == 0);
    CHECK(sucrune_signals_return(&thread, &memory, &cpu) == 0);
    thread.mask = bit(10); raise_signal(10U);
    CHECK(install(10U, 1U, 0U, 0U) == 0);
    CHECK(sucrune_signals_deliver(&process, &thread, &memory, &cpu, &termination) == SUCRUNE_SIGNAL_NONE && thread.pending == 0U);
    raise_signal(17U); CHECK(thread.pending == 0U); /* default SIGCHLD ignores */
    raise_signal(9U);
    CHECK(sucrune_signals_deliver(&process, &thread, &memory, &cpu, &termination) == SUCRUNE_SIGNAL_TERMINATE && termination == 9);
    cases++;
}
static void alternate_stacks(void) {
    reset();
    const uint64_t initial_sp = cpu.sp;
    const uintptr_t buffer = data() + 128U;
    struct sucrune_signal_stack *request = (void *)buffer;
    struct sucrune_signal_stack desired = {.sp = data() + 4096U, .size = 16391U};
    *request = desired;
    CHECK(sucrune_signals_altstack(&thread.altstack, &memory, cpu.sp, buffer, buffer) == 0);
    CHECK(request->flags == SUCRUNE_SS_DISABLE && request->sp == 0U && request->size == 0U);
    CHECK(install(10U, base() + 512U, SUCRUNE_SIGNAL_SA_ONSTACK | SUCRUNE_SIGNAL_SA_NODEFER, 0U) == 0);
    enter(10U);
    uintptr_t first = (uintptr_t)cpu.sp;
    CHECK(first > desired.sp && first < desired.sp + desired.size && (first & 15U) == 0U);
    const struct sucrune_signal_frame *frame = (void *)first;
    CHECK(frame->context.machine.sp == initial_sp && frame->context.stack.flags == 0);
    CHECK(frame->context.stack.sp == desired.sp && frame->context.stack.size == desired.size);
    CHECK(sucrune_signals_altstack(&thread.altstack, &memory, cpu.sp, 0U, buffer) == 0);
    CHECK(request->flags == SUCRUNE_SS_ONSTACK);
    CHECK(sucrune_signals_altstack(&thread.altstack, &memory, cpu.sp, buffer, 0U) == -EPERM);
    enter(10U);
    CHECK(cpu.sp > desired.sp && cpu.sp < first);
    CHECK(sucrune_signals_return(&thread, &memory, &cpu) == 0 && cpu.sp == first);
    CHECK(sucrune_signals_return(&thread, &memory, &cpu) == 0 && cpu.sp == initial_sp);

    *request = desired;
    request->flags = (int32_t)SUCRUNE_SS_AUTODISARM;
    CHECK(sucrune_signals_altstack(&thread.altstack, &memory, cpu.sp, buffer, 0U) == 0);
    enter(10U);
    CHECK(sucrune_signals_altstack(&thread.altstack, &memory, cpu.sp, 0U, buffer) == 0);
    CHECK(request->flags == SUCRUNE_SS_DISABLE);
    CHECK(sucrune_signals_return(&thread, &memory, &cpu) == 0);
    CHECK(sucrune_signals_altstack(&thread.altstack, &memory, cpu.sp, 0U, buffer) == 0);
    CHECK((uint32_t)request->flags == SUCRUNE_SS_AUTODISARM && request->sp == desired.sp);

    *request = desired;
    request->size = SUCRUNE_MINSIGSTKSZ - 1U;
    CHECK(sucrune_signals_altstack(&thread.altstack, &memory, cpu.sp, buffer, 0U) == -ENOMEM);
    request->size++;
    CHECK(sucrune_signals_altstack(&thread.altstack, &memory, cpu.sp, buffer, 0U) == 0);
    enter(10U);
    raise_signal(10U);
    int termination = -1;
    CHECK(sucrune_signals_deliver(&process, &thread, &memory, &cpu, &termination) == -EFAULT);
    CHECK(thread.depth == 1U && thread.pending == bit(10));
    CHECK(sucrune_signals_return(&thread, &memory, &cpu) == 0);
    request->flags = SUCRUNE_SS_DISABLE;
    CHECK(sucrune_signals_altstack(&thread.altstack, &memory, cpu.sp, buffer, buffer) == 0);
    CHECK(request->size == SUCRUNE_MINSIGSTKSZ && request->flags == 0 && thread.altstack.size == 0U);
    request->flags = 8;
    CHECK(sucrune_signals_altstack(&thread.altstack, &memory, cpu.sp, buffer, 0U) == -EINVAL);
    cases++;
}
static void node_reset_then_raise(void) {
    reset();
    struct sucrune_signal_cpu original = cpu;
    CHECK(install(15U, base() + 512U, SUCRUNE_SIGNAL_SA_RESETHAND, UINT64_MAX) == 0);
    enter(15U);
    CHECK(process.actions[15].handler == 0U && (thread.mask & bit(15)) != 0U);
    raise_signal(15U); /* Node SignalExit calls raise while blocked. */
    int termination = -1;
    CHECK(sucrune_signals_deliver(&process, &thread, &memory, &cpu, &termination) == SUCRUNE_SIGNAL_NONE);
    CHECK(sucrune_signals_return(&thread, &memory, &cpu) == 0 && memcmp(&cpu, &original, sizeof(cpu)) == 0);
    CHECK(sucrune_signals_deliver(&process, &thread, &memory, &cpu, &termination) == SUCRUNE_SIGNAL_TERMINATE && termination == 15);
    cases++;
}
static void bounded_nested_delivery(void) {
    reset();
    struct sucrune_signal_cpu original = cpu;
    CHECK(install(10U, base() + 512U, SUCRUNE_SIGNAL_SA_NODEFER, 0U) == 0);
    for (unsigned int i = 0U; i < SUCRUNE_SIGNAL_DEPTH; i++) { enter(10U); CHECK(thread.depth == i + 1U && thread.mask == 0U); }
    raise_signal(10U);
    struct sucrune_signal_cpu deepest = cpu;
    int termination = -1;
    CHECK(sucrune_signals_deliver(&process, &thread, &memory, &cpu, &termination) == -EOVERFLOW);
    CHECK(memcmp(&cpu, &deepest, sizeof(cpu)) == 0 && thread.depth == 8U && thread.pending == bit(10));
    thread.pending = 0U;
    for (unsigned int i = 0U; i < SUCRUNE_SIGNAL_DEPTH; i++) CHECK(sucrune_signals_return(&thread, &memory, &cpu) == 0);
    CHECK(memcmp(&cpu, &original, sizeof(cpu)) == 0 && thread.depth == 0U);
    cases++;
}
static void edited_context_and_bad_frames(void) {
    reset();
    CHECK(install(12U, base() + 512U, SUCRUNE_SIGNAL_SA_SIGINFO, 0U) == 0);
    enter(12U);
    struct sucrune_signal_frame *frame = (void *)(uintptr_t)cpu.sp;
    uint64_t old_pc = frame->context.machine.pc;
    frame->context.machine.pc = data();
    CHECK(sucrune_signals_return(&thread, &memory, &cpu) == -EFAULT && thread.depth == 1U);
    frame->context.machine.pc = old_pc;
    frame->context.machine.pstate |= 1U;
    CHECK(sucrune_signals_return(&thread, &memory, &cpu) == -EFAULT && thread.depth == 1U);
    frame->context.machine.pstate &= SUCRUNE_SIGNAL_NZCV;
    frame->context.machine.reserved[528] = 1U; /* unknown/extra record rejected */
    CHECK(sucrune_signals_return(&thread, &memory, &cpu) == -EINVAL && thread.depth == 1U);
    frame->context.machine.reserved[528] = 0U;
    /* Linux ignores invalid changes to uc_stack on return. */
    frame->context.stack.flags = 8;
    cpu.sp += 16U;
    CHECK(sucrune_signals_return(&thread, &memory, &cpu) == -EINVAL);
    cpu.sp -= 16U;
    frame->context.machine.pc = base() + 1024U; frame->context.machine.regs[0] = 4242U;
    frame->context.machine.regs[18] = UINT64_C(0xf0001234);
    frame->context.mask = bit(2) | bit(9) | bit(19);
    struct sucrune_signal_fpsimd fpsimd;
    memcpy(&fpsimd, frame->context.machine.reserved, sizeof(fpsimd));
    fpsimd.vectors[63] = UINT64_C(0x1234567890); fpsimd.fpcr = 0x800000U;
    memcpy(frame->context.machine.reserved, &fpsimd, sizeof(fpsimd));
    CHECK(sucrune_signals_return(&thread, &memory, &cpu) == 0);
    CHECK(cpu.pc == base() + 1024U && cpu.regs[0] == 4242U && cpu.regs[18] == UINT64_C(0xf0001234));
    CHECK(cpu.vectors[63] == UINT64_C(0x1234567890) && cpu.fpcr == 0x800000U && thread.mask == bit(2));
    cases++;
}
static void identities_and_boundaries(void) {
    reset();
    CHECK(sucrune_signals_self(&process, &thread, 129U, 71, 0, 0) == 0);
    CHECK(sucrune_signals_self(&process, &thread, 129U, 999, 0, 0) == -ESRCH);
    CHECK(sucrune_signals_self(&process, &thread, 129U, 0, 15, 0) == -ENOTSUP);
    CHECK(sucrune_signals_self(&process, &thread, 130U, 71, 15, 0) == -ESRCH);
    CHECK(sucrune_signals_self(&process, &thread, 131U, 71, 999, 15) == -ESRCH);
    CHECK(sucrune_signals_self(&process, &thread, 131U, 71, 72, 65) == -EINVAL);
    CHECK(sucrune_signals_self(&process, &thread, 131U, 71, 72, 34) == -ENOTSUP);
    CHECK(sucrune_signals_self(&process, &thread, 131U, 71, 72, 19) == -ENOTSUP);
    CHECK(install(10U, base() + 512U, 0U, 0U) == 0);
    raise_signal(10U);
    struct sucrune_signal_cpu original = cpu;
    memory.restorer = data();
    int termination = -1;
    CHECK(sucrune_signals_deliver(&process, &thread, &memory, &cpu, &termination) == -EFAULT);
    CHECK(memcmp(&cpu, &original, sizeof(cpu)) == 0 && thread.depth == 0U && thread.pending == bit(10));
    memory.restorer = base() + 256U;
    cpu.sp = data() + 16U;
    CHECK(sucrune_signals_deliver(&process, &thread, &memory, &cpu, &termination) == -EFAULT);
    CHECK(thread.depth == 0U && thread.pending == bit(10));
    cases++;
}
int main(void) {
    actions_and_mask(); frame_and_roundtrip(); masking_coalescing_and_dispositions(); alternate_stacks();
    node_reset_then_raise(); bounded_nested_delivery(); edited_context_and_bad_frames(); identities_and_boundaries();
    printf("guest_signals: %u host groups passed; native handler execution is not claimed\n", cases);
    return 0;
}
