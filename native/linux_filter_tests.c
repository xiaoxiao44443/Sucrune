/* Compile with a generated header containing the verbatim filter_range and
 * linux_filter functions extracted from shell_runtime.c. This test interprets
 * their emitted classic BPF, not a second implementation of their generator.
 * It does not install a filter and does not establish Android kernel behavior. */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BPF_LD 0x00U
#define BPF_W 0x00U
#define BPF_ABS 0x20U
#define BPF_JMP 0x05U
#define BPF_JEQ 0x10U
#define BPF_JGT 0x20U
#define BPF_JGE 0x30U
#define BPF_K 0x00U
#define BPF_RET 0x06U
#define BPF_STMT(operation, value) { (unsigned short)(operation), 0U, 0U, (value) }
#define BPF_JUMP(operation, value, yes, no) { (unsigned short)(operation), (yes), (no), (value) }
#define SECCOMP_RET_KILL_PROCESS UINT32_C(0x80000000)
#define SECCOMP_RET_TRAP UINT32_C(0x00030000)
#define SECCOMP_RET_ALLOW UINT32_C(0x7fff0000)
#define AUDIT_ARCH_AARCH64 UINT32_C(0xc00000b7)
#define PR_SET_SECCOMP 22
#define SECCOMP_MODE_FILTER 2
struct sock_filter { unsigned short code; unsigned char jt, jf; uint32_t k; };
struct sock_fprog { unsigned short len; struct sock_filter *filter; };
struct seccomp_data { int nr; uint32_t arch; uint64_t instruction_pointer; uint64_t args[6]; };
struct test_space { uintptr_t base; size_t size; };
struct shell_state { struct test_space space, fixed_space; };
static struct sock_filter emitted[32];
static size_t emitted_count;
static unsigned int checks, configurations;
#define CHECK(condition) do { if (!(condition)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); exit(1); } } while (0)
static int capture_prctl(int operation, int mode, const struct sock_fprog *program) {
    CHECK(operation == PR_SET_SECCOMP && mode == SECCOMP_MODE_FILTER);
    CHECK(program->len > 0U && program->len <= 32U);
    emitted_count = program->len;
    memcpy(emitted, program->filter, emitted_count * sizeof(emitted[0]));
    return 0;
}
#define prctl capture_prctl
#include "linux_filter_generated.h"
#undef prctl

static uint32_t interpret(uint64_t pc, uint32_t architecture) {
    struct seccomp_data input = { .nr = 94, .arch = architecture, .instruction_pointer = pc };
    uint32_t accumulator = 0U;
    size_t cursor = 0U;
    for (unsigned int steps = 0U; steps < 100U; steps++) {
        CHECK(cursor < emitted_count);
        const struct sock_filter *instruction = &emitted[cursor++];
        if (instruction->code == (BPF_LD | BPF_W | BPF_ABS)) {
            CHECK(instruction->k % sizeof(uint32_t) == 0U && instruction->k <= sizeof(input) - sizeof(uint32_t));
            memcpy(&accumulator, (const unsigned char *)&input + instruction->k, sizeof(accumulator));
        } else if (instruction->code == (BPF_RET | BPF_K)) return instruction->k;
        else {
            int taken = 0;
            if (instruction->code == (BPF_JMP | BPF_JEQ | BPF_K)) taken = accumulator == instruction->k;
            else if (instruction->code == (BPF_JMP | BPF_JGT | BPF_K)) taken = accumulator > instruction->k;
            else if (instruction->code == (BPF_JMP | BPF_JGE | BPF_K)) taken = accumulator >= instruction->k;
            else CHECK(0);
            cursor += taken != 0 ? instruction->jt : instruction->jf;
        }
    }
    CHECK(0); return 0U;
}
static int guest_resume_pc(const struct test_space *space, uint64_t pc) {
    /* An AArch64 svc occupies four bytes; seccomp observes the resume PC.
     * All generated instructions must stay in [base,base+size), making the
     * corresponding resume-PC interval (base,base+size]. */
    return space->base != 0U && pc > space->base && pc - space->base <= space->size;
}
static void verify(const struct shell_state *state, uint64_t pc, uint32_t arch) {
    uint32_t want = arch != AUDIT_ARCH_AARCH64 ? SECCOMP_RET_KILL_PROCESS :
        guest_resume_pc(&state->space, pc) || guest_resume_pc(&state->fixed_space, pc) ? SECCOMP_RET_TRAP | SHELL_TAG : SECCOMP_RET_ALLOW;
    uint32_t actual = interpret(pc, arch);
    if (actual != want) {
        fprintf(stderr, "BPF mismatch pc=%llx arch=%x got=%x expected=%x main=%llx+%llx fixed=%llx+%llx\n",
            (unsigned long long)pc, arch, actual, want,
            (unsigned long long)state->space.base, (unsigned long long)state->space.size,
            (unsigned long long)state->fixed_space.base, (unsigned long long)state->fixed_space.size);
        exit(1);
    }
    checks++;
}
static void boundaries(const struct shell_state *state, const struct test_space *space) {
    if (space->base == 0U) return;
    uint64_t begin = space->base, end = begin + space->size;
    uint64_t points[] = {begin - 1U, begin, begin + 1U, begin + 4U, end - 4U, end - 1U, end, end + 1U, end + 4U};
    for (size_t i = 0U; i < sizeof(points) / sizeof(points[0]); i++) {
        verify(state, points[i], AUDIT_ARCH_AARCH64);
        verify(state, points[i], UINT32_C(0xc000003e));
    }
    uint64_t boundary = (begin & ~UINT64_C(0xffffffff)) + UINT64_C(0x100000000);
    if (boundary > begin && boundary < end) {
        verify(state, boundary - 1U, AUDIT_ARCH_AARCH64);
        verify(state, boundary, AUDIT_ARCH_AARCH64);
        verify(state, boundary + 1U, AUDIT_ARCH_AARCH64);
    }
}
static void configuration(uintptr_t low, size_t size, uintptr_t fixed, size_t fixed_size) {
    struct shell_state state = { .space = {low, size}, .fixed_space = {fixed, fixed_size} };
    CHECK(linux_filter(&state) == 0);
    CHECK(emitted_count == (fixed != 0U ? 26U : 15U));
    boundaries(&state, &state.space); boundaries(&state, &state.fixed_space);
    verify(&state, 0U, AUDIT_ARCH_AARCH64);
    verify(&state, UINT64_MAX, AUDIT_ARCH_AARCH64);
    verify(&state, low + size / 2U, AUDIT_ARCH_AARCH64);
    configurations++;
}
int main(void) {
    configuration(UINT64_C(0x400000), UINT64_C(0x6800000), 0U, 0U);
    configuration(UINT64_C(0xfffff000), UINT64_C(0x2000), 0U, 0U);
    configuration(UINT64_C(0xff000000), UINT64_C(0x1000000), 0U, 0U);
    configuration(UINT64_C(0x700080000000), UINT64_C(0x1000000000), UINT64_C(0x400000), UINT64_C(0x6800000));
    uint64_t random = UINT64_C(0x71ac064b9f3e201d);
    for (unsigned int i = 0U; i < 4096U; i++) {
        random = random * UINT64_C(6364136223846793005) + 1U;
        uintptr_t low = (uintptr_t)((random & UINT64_C(0x7ffffffff000)) | UINT64_C(0x10000));
        size_t size = (size_t)((random >> 32U) % UINT64_C(0x1000000) + 1U) * 4096U;
        configuration(low, size, i % 2U != 0U ? UINT64_C(0x400000) : 0U, UINT64_C(0x6800000));
    }
    printf("Linux filter checks: %u decisions across %u source-generated configurations passed.\n", checks, configurations);
    return 0;
}
