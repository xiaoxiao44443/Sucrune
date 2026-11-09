#if defined(__aarch64__)
.text
.p2align 4
.global sucrune_guest_thread_enter
.hidden sucrune_guest_thread_enter
.type sucrune_guest_thread_enter, %function
/* x0=host, x1=thread, x2=guest TLS, x3=guest x18, x4=pid, x5=tid.
 * Save host context before C registers the gate. The existing signal gate
 * handles the bootstrap signal with host TLS and restores guest TLS before
 * the kernel restores ALL guest GPR/FPSIMD state from the real signal frame. */
sucrune_guest_thread_enter:
    hint #34
    stp x19, x20, [x0, #0]
    stp x21, x22, [x0, #16]
    stp x23, x24, [x0, #32]
    stp x25, x26, [x0, #48]
    stp x27, x28, [x0, #64]
    stp x29, x30, [x0, #80]
    stp d8, d9, [x0, #96]
    stp d10, d11, [x0, #112]
    stp d12, d13, [x0, #128]
    stp d14, d15, [x0, #144]
    mov x9, sp
    stp x9, x18, [x0, #160]
    mrs x9, fpcr
    mrs x10, fpsr
    stp x9, x10, [x0, #176]
    mrs x9, tpidr_el0
    str x9, [x0, #192]
    mov x19, x0
    mov x20, x1
    mov x21, x2
    mov x22, x3
    mov x23, x4
    mov x24, x5
    mov x0, x20
    bl sucrune_thread_before_enter
    cbnz x0, .Lthread_return
    msr tpidr_el0, x21
    mov x18, x22
    mov x0, x23
    mov x1, x24
    mov x2, #12 // SIGUSR2, reserved by this standalone runner
    mov x8, #131 // tgkill to this host pthread
    svc #0
    // A successful bootstrap returns from its signal frame into guest PC.
    // Returning here indicates failed/blocked delivery; never use guest TLS C.
    mov x0, #159
    mov x8, #94
    svc #0
    b .
.Lthread_return:
    mov x0, x19
    b sucrune_guest_return
.size sucrune_guest_thread_enter, .-sucrune_guest_thread_enter
.section .note.GNU-stack,"",%progbits
#endif
