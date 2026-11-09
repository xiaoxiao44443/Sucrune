#if defined(__aarch64__)
.text
.p2align 4
.global sucrune_guest_enter
.hidden sucrune_guest_enter
.type sucrune_guest_enter, %function
/* x0=entry, x1=guest initial SP, x2=host context, w3=Linux ABI. */
sucrune_guest_enter:
    hint #34 // BTI c (a NOP on older hardware)
    stp x19, x20, [x2, #0]
    stp x21, x22, [x2, #16]
    stp x23, x24, [x2, #32]
    stp x25, x26, [x2, #48]
    stp x27, x28, [x2, #64]
    stp x29, x30, [x2, #80]
    stp d8, d9, [x2, #96]
    stp d10, d11, [x2, #112]
    stp d12, d13, [x2, #128]
    stp d14, d15, [x2, #144]
    mov x9, sp
    stp x9, x18, [x2, #160]
    mrs x9, fpcr
    mrs x10, fpsr
    stp x9, x10, [x2, #176]
    mrs x9, tpidr_el0
    str x9, [x2, #192]
    mov x16, x0
    mov sp, x1
    cbz w3, 1f
    // Linux exec starts with an unallocated TP. Do not let Go's
    // clone-without-CLONE_SETTLS inherit this Bionic thread's control block.
    msr tpidr_el0, xzr
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr
    mov x4, xzr
    mov x5, xzr
    mov x6, xzr
    mov x7, xzr
    mov x8, xzr
    mov x9, xzr
    mov x10, xzr
    mov x11, xzr
    mov x12, xzr
    mov x13, xzr
    mov x14, xzr
    mov x15, xzr
    mov x17, xzr
    mov x18, xzr
    mov x19, xzr
    mov x20, xzr
    mov x21, xzr
    mov x22, xzr
    mov x23, xzr
    mov x24, xzr
    mov x25, xzr
    mov x26, xzr
    mov x27, xzr
    mov x28, xzr
1:
    mov x0, #0
    mov x29, #0
    mov x30, #0
    br x16
.size sucrune_guest_enter, .-sucrune_guest_enter

.global sucrune_guest_return
.hidden sucrune_guest_return
.type sucrune_guest_return, %function
/* SIGSYS exit changes PC to here and x0 to the saved host context.
 * The kernel has already restored its signal mask and left the alt stack. */
sucrune_guest_return:
    hint #34
    ldr x9, [x0, #192]
    msr tpidr_el0, x9
    ldp x9, x18, [x0, #160]
    mov sp, x9
    ldp x9, x10, [x0, #176]
    msr fpcr, x9
    msr fpsr, x10
    ldp d8, d9, [x0, #96]
    ldp d10, d11, [x0, #112]
    ldp d12, d13, [x0, #128]
    ldp d14, d15, [x0, #144]
    ldp x19, x20, [x0, #0]
    ldp x21, x22, [x0, #16]
    ldp x23, x24, [x0, #32]
    ldp x25, x26, [x0, #48]
    ldp x27, x28, [x0, #64]
    ldp x29, x30, [x0, #80]
    mov x0, #0
    ret
.size sucrune_guest_return, .-sucrune_guest_return
.section .note.GNU-stack,"",%progbits
#endif
