#if defined(__aarch64__)
#include "guest_fork_arena.h"
.text
.p2align 4
.global sucrune_fork_raw_clone
.hidden sucrune_fork_raw_clone
.type sucrune_fork_raw_clone,%function
// flags, top of child stack, raw entry, argument. No inherited libc thread API.
sucrune_fork_raw_clone:
    hint #34
    sub x1,x1,#16
    stp x2,x3,[x1]
    mov x2,xzr
    mov x3,xzr
    mov x4,xzr
    mov x8,#220
    svc #0
    cbnz x0,1f
    ldp x16,x0,[sp],#16
    blr x16
    mov x0,#125
    mov x8,#94
    svc #0
1:  ret
.size sucrune_fork_raw_clone,.-sucrune_fork_raw_clone

/* Enter with x0 = aligned arena. Both the ordinary fork and shared-VM child
 * switch to private supervisor scratch TLS and SCS before invoking C. */
.global sucrune_fork_arena_enter
.hidden sucrune_fork_arena_enter
.type sucrune_fork_arena_enter,%function
sucrune_fork_arena_enter:
    hint #34
    mov x10,#(SUCRUNE_FORK_SUPERVISOR_TOP >> 16)
    add x10,x0,x10,lsl #16
    mov sp,x10
    ldp x10,x18,[x0,#16]
    msr tpidr_el0,x10
    b sucrune_fork_supervisor
.size sucrune_fork_arena_enter,.-sucrune_fork_arena_enter

.global sucrune_fork_signal_entry
.hidden sucrune_fork_signal_entry
.type sucrune_fork_signal_entry,%function
sucrune_fork_signal_entry:
    hint #34
    mrs x9,tpidr_el0
    stp x9,x18,[sp,#-32]!
    str x30,[sp,#16]
    mov x3,x9
    mov x9,sp
    and x9,x9,#-SUCRUNE_FORK_ARENA_BYTES
    ldp x10,x18,[x9]
    msr tpidr_el0,x10
    bl sucrune_fork_handle_signal
    ldr x30,[sp,#16]
    ldp x9,x18,[sp],#32
    msr tpidr_el0,x9
    ret
.size sucrune_fork_signal_entry,.-sucrune_fork_signal_entry

.global sucrune_fork_resume
.hidden sucrune_fork_resume
.type sucrune_fork_resume,%function
sucrune_fork_resume:
    hint #34
    msr tpidr_el0,x0
    mov x18,x1
    mov x0,x2
    mov x1,x3
    mov x2,#12
    mov x8,#131
    svc #0
    mov x0,#125
    mov x8,#94
    svc #0
    brk #0
.size sucrune_fork_resume,.-sucrune_fork_resume

.global sucrune_fork_restorer
.hidden sucrune_fork_restorer
.type sucrune_fork_restorer,%function
sucrune_fork_restorer:
    mov x8,#139
    svc #0
    brk #0
.size sucrune_fork_restorer,.-sucrune_fork_restorer
.section .note.GNU-stack,"",%progbits
#endif
