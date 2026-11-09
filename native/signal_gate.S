#if defined(__aarch64__)
#include "guest_fault.h"
.text
.p2align 4
.global sucrune_signal_entry
.hidden sucrune_signal_entry
.type sucrune_signal_entry, %function
/* The kernel arrives with the guest's TPIDR_EL0 and x18. No C, TLS access,
 * PLT call or shadow-call-stack instrumentation may precede this gate.
 * The interrupted register frame remains owned by the kernel. */
sucrune_signal_entry:
    hint #34
    stp x0, x1, [sp, #-64]!
    stp x2, x30, [sp, #16]
    mrs x10, tpidr_el0
    stp x10, x18, [sp, #32]
    // A process-wide signal handler must not borrow another thread's TLS.
    mov x8, #178 // __NR_gettid
    svc #0
    mov x15, x0
    adrp x14, sucrune_signal_gate_count
    add x14, x14, :lo12:sucrune_signal_gate_count
    ldar w14, [x14]
    cbz w14, .Lgate_legacy
    // Match immutable sidecar TIDs before touching gate memory. Dereferencing
    // every gate just to inspect its TID would race retirement by its owner.
    adrp x11, sucrune_signal_gate_tids
    add x11, x11, :lo12:sucrune_signal_gate_tids
    adrp x12, sucrune_signal_gate_slots
    add x12, x12, :lo12:sucrune_signal_gate_slots
    mov x13, #64
.Lgate_scan:
    ldar x10, [x11]
    cmp x15, x10
    b.ne .Lgate_next
    ldar x9, [x12]
    cbz x9, .Lgate_next
    ldar x10, [x11]
    cmp x15, x10
    b.ne .Lgate_next
    b .Lgate_match
.Lgate_next:
    add x11, x11, #8
    add x12, x12, #8
    subs x13, x13, #1
    b.ne .Lgate_scan
    // Old single-thread probes publish only this global. Registered threads
    // never need to inspect it, and existing callers keep their old lifetime.
.Lgate_legacy:
    adrp x9, sucrune_active_signal_gate
    add x9, x9, :lo12:sucrune_active_signal_gate
    ldar x9, [x9]
    cbz x9, .Lgate_fatal
.Lgate_match:
    ldr x10, [x9, #16]
    cmp x15, x10
    b.ne .Lgate_fatal
    str x9, [sp, #48]
    ldp x10, x11, [sp, #32]
    stp x10, x11, [x9, #24]
    ldr x10, [x9, #40]
    add x10, x10, #1
    str x10, [x9, #40]
    ldr x10, [x9]
    cbz x10, .Lgate_fatal
    ldr x11, [x10, #192]
    msr tpidr_el0, x11
    ldr x18, [x10, #168]
    ldr x16, [x9, #8]
    cbz x16, .Lgate_fatal
    ldp x0, x1, [sp]
    ldr x2, [sp, #16]
    blr x16
    // The libc handler has returned. The restorer is assembly-only; Linux
    // rt_sigreturn restores GPRs but does not switch TPIDR_EL0 for us.
    ldp x10, x18, [sp, #32]
    msr tpidr_el0, x10
    ldr x30, [sp, #24]
    add sp, sp, #64
    ret
.Lgate_fatal:
    mov x0, #159
    mov x8, #94 // __NR_exit_group
    svc #0
    b .Lgate_fatal
.size sucrune_signal_entry, .-sucrune_signal_entry

.p2align 4
.global sucrune_guest_fatal_signal
.hidden sucrune_guest_fatal_signal
.type sucrune_guest_fatal_signal, %function
/* Android crash handlers cannot run under an arbitrary guest TLS pointer. */
sucrune_guest_fatal_signal:
    hint #34
    add x0, x0, #128
    mov x8, #94
    svc #0
    b sucrune_guest_fatal_signal
.size sucrune_guest_fatal_signal, .-sucrune_guest_fatal_signal

/* Optional diagnostic on the kernel's altstack. It never follows a guest
 * pointer, acquires a lock, uses TLS, or prints an address outside a
 * published guest range. Its single bounded write precedes the same exit. */
.macro fault_text label
    adrp x5, \label
    add x5, x5, :lo12:\label
.Lfault_copy\@:
    ldrb w6, [x5], #1
    cbz w6, .Lfault_text_end\@
    strb w6, [x22], #1
    b .Lfault_copy\@
.Lfault_text_end\@:
.endm
.p2align 4
.global sucrune_guest_trace_fault
.hidden sucrune_guest_trace_fault
.type sucrune_guest_trace_fault, %function
sucrune_guest_trace_fault:
    hint #34
    mov x19, x0                   // signum, siginfo, ucontext from kernel
    mov x20, x1
    mov x21, x2
    cbz x20, .Ltrace_exit
    cbz x21, .Ltrace_exit
    sub sp, sp, #144
    mov x22, sp                   // output cursor
    adrp x5, sucrune_fault_map
    add x5, x5, :lo12:sucrune_fault_map
    ldar x23, [x5]                // immutable across the entire handler
    fault_text .Lfault_prefix
    mov x4, x19
    mov w7, #2
    bl .Lfault_hex
    fault_text .Lfault_code
    ldr w24, [x20, #SUCRUNE_FAULT_SI_CODE]
    mov w4, w24
    mov w7, #8
    bl .Lfault_hex
    fault_text .Lfault_pc
    ldr x4, [x21, #SUCRUNE_FAULT_UC_PC]
    bl .Lfault_location
    fault_text .Lfault_addr
    cmp w24, #0                   // si_addr is not valid for user-sent signals
    b.le .Lfault_noaddr
    cmp w19, #6                   // SIGABRT has no hardware fault address
    b.eq .Lfault_noaddr
    ldr x4, [x20, #SUCRUNE_FAULT_SI_ADDR]
    bl .Lfault_location
    b .Lfault_flush
.Lfault_noaddr:
    fault_text .Lfault_none
.Lfault_flush:
    mov w6, #10
    strb w6, [x22], #1
    mov x1, sp
    sub x2, x22, x1
    mov x0, #2
    mov x8, #64                   // write(stderr, line, length)
    svc #0
.Ltrace_exit:
    add x0, x19, #128
    mov x8, #94                   // exit_group
    svc #0
    b .Ltrace_exit
.Lfault_location:
    cmp x4, #1, lsl #12
    b.lo .Lfault_near_zero
    cbz x23, .Lfault_unknown
    mov x9, #0
.Lfault_range:
    add x5, x23, x9, lsl #4
    ldp x6, x7, [x5]              // host-owned base, byte length
    sub x8, x4, x6
    cmp x8, x7
    b.lo .Lfault_owned
    add x9, x9, #1
    cmp x9, #4
    b.lo .Lfault_range
.Lfault_unknown:
    fault_text .Lfault_outside
    ret
.Lfault_owned:
    mov x4, x8                    // only this relative offset may leave the process
    cbz x9, .Lfault_main
    cmp x9, #1
    b.eq .Lfault_loader
    cmp x9, #2
    b.eq .Lfault_exact
    fault_text .Lfault_arena
    b .Lfault_offset
.Lfault_main:
    fault_text .Lfault_image
    b .Lfault_offset
.Lfault_loader:
    fault_text .Lfault_interp
    b .Lfault_offset
.Lfault_exact:
    fault_text .Lfault_fixed
    b .Lfault_offset
.Lfault_near_zero:
    fault_text .Lfault_null
.Lfault_offset:
    mov w7, #16
.Lfault_hex:                      // x4 value; w7 nibbles; x22 cursor
    sub w7, w7, #1
    lsl w5, w7, #2
    lsr x6, x4, x5
    and w6, w6, #15
    cmp w6, #10
    add w5, w6, #48
    add w6, w6, #87
    csel w5, w5, w6, lo
    strb w5, [x22], #1
    cbnz w7, .Lfault_hex
    ret
.size sucrune_guest_trace_fault, .-sucrune_guest_trace_fault

.section .rodata
.Lfault_prefix:  .asciz "sucrune-fault sig=0x"
.Lfault_code:    .asciz " code=0x"
.Lfault_pc:      .asciz " pc="
.Lfault_addr:    .asciz " addr="
.Lfault_none:    .asciz "unavailable"
.Lfault_outside: .asciz "outside"
.Lfault_arena:   .asciz "arena+0x"
.Lfault_image:   .asciz "image+0x"
.Lfault_interp:  .asciz "interp+0x"
.Lfault_fixed:   .asciz "fixed+0x"
.Lfault_null:    .asciz "near-null+0x"

.bss
.p2align 3
.global sucrune_fault_map
.hidden sucrune_fault_map
.type sucrune_fault_map, %object
sucrune_fault_map:
    .zero 8
.size sucrune_fault_map, 8
.p2align 3
.global sucrune_active_signal_gate
.hidden sucrune_active_signal_gate
.type sucrune_active_signal_gate, %object
.size sucrune_active_signal_gate, 8
sucrune_active_signal_gate:
    .zero 8
.p2align 3
.global sucrune_signal_gate_slots
.hidden sucrune_signal_gate_slots
.type sucrune_signal_gate_slots, %object
.size sucrune_signal_gate_slots, 512
sucrune_signal_gate_slots:
    .zero 512
.p2align 3
.global sucrune_signal_gate_tids
.hidden sucrune_signal_gate_tids
.type sucrune_signal_gate_tids, %object
.size sucrune_signal_gate_tids, 512
sucrune_signal_gate_tids:
    .zero 512
.p2align 2
.global sucrune_signal_gate_count
.hidden sucrune_signal_gate_count
.type sucrune_signal_gate_count, %object
.size sucrune_signal_gate_count, 4
sucrune_signal_gate_count:
    .zero 4
.section .note.GNU-stack,"",%progbits
#endif
