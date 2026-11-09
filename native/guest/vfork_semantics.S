/* AArch64 Linux clone(VM|VFORK|SIGCHLD). The unused parent_tid argument
 * is non-null as it is in Go's syscall.forkAndExecInChild1. */
.text
.global _start
.type _start,%function
_start:
    adrp x19, shared
    add x19, x19, :lo12:shared
    add x22, x19, #12
    mov x0, #0x0f00
    movk x0, #0x125, lsl #16 // Thread group, CHILD_SETTID, CHILD_CLEARTID.
    adrp x1, sibling_top
    add x1, x1, :lo12:sibling_top
    mov x2, xzr
    mov x3, xzr
    add x4, x19, #16
    mov x8, #220
    svc #0
    cbz x0, .Lsibling
    tbnz x0, #63, .Lfail
    mov x20, #1
.Lclone:
    str wzr, [x19]
    mov w10, #-1
    str w10, [x19, #24]
    mov x0, #0x4111
    movk x0, #0x120, lsl #16  // CHILD_SETTID | CHILD_CLEARTID
    mov x1, xzr
    add x2, x19, #4
    mov x3, xzr
    add x4, x19, #20
    mov x8, #220
    svc #0
    cbz x0, .Lchild
    tbnz x0, #63, .Lfail
    mov x21, x0
    ldr w10, [x19]           // Must be visible BEFORE parent wait4.
    cmp w10, w20
    b.ne .Lfail
    ldr w10, [x19, #20]
    cmp x20, #1
    b.ne .Lcheck_exec_tid
    cmp w10, w21              // set_tid_address superseded the original.
    b.ne .Lfail
    ldr w10, [x19, #24]
.Lcheck_exec_tid:
    cbnz w10, .Lfail
    add x1, x19, #8
    mov x2, xzr
    adrp x3, usage
    add x3, x3, :lo12:usage
    str xzr, [x3, #32]
    mov x8, #260
    svc #0
    cmp x0, x21
    b.ne .Lfail
    adrp x3, usage
    add x3, x3, :lo12:usage
    ldr x10, [x3, #32]       // Linux/AArch64 struct rusage.ru_maxrss
    cmp x10, #0
    b.le .Lfail
    ldr w10, [x19, #8]
    cmp x20, #1
    b.ne .Lcheck_exec
    mov w11, #0x2400         // First child exits with status 36.
    cmp w10, w11
    b.ne .Lfail
    mov x20, #2
    b .Lclone
.Lcheck_exec:
    cbnz w10, .Lfail
    // An ordinary fork child can vfork while still in its shell continuation.
    mov x0, #17
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr
    mov x4, xzr
    mov x8, #220
    svc #0
    tbnz x0, #63, .Lfail
    cbz x0, .Lnested
    mov x21, x0
    add x1, x19, #8
    mov x2, xzr
    mov x3, xzr
    mov x8, #260
    svc #0
    cmp x0, x21
    b.ne .Lfail
    ldr w10, [x19, #8]
    cbnz w10, .Lfail
    add x23, x19, #16
.Ljoin:
    ldar w10, [x23]
    cbnz w10, .Ljoin
    adr x1, passed
    mov x2, #(passed_end-passed)
    b .Lprint
.Lchild:
    mov x8, #172
    svc #0
    ldr w10, [x19, #20]      // Real guest PID is published before entry.
    cmp w10, w0
    b.ne .Lfail
    // Parent returning immediately under a plain non-blocking clone will
    // read zero before this child publishes its marker.
    adrp x0, delay
    add x0, x0, :lo12:delay
    mov x1, xzr
    mov x8, #101             // nanosleep
    svc #0
    cbnz x0, .Lfail
    cmp x20, #1
    b.ne .Lexec
    // A sibling must be able to trap gettid before the vfork child exits.
    // Suspending all threads under the guest-state mutex deadlocks this pair.
    mov w10, #1
    stlr w10, [x22]
    mov w12, #40
.Lwait_sibling:
    ldar w10, [x22]
    cmp w10, #2
    b.eq .Lsibling_ready
    adr x0, delay
    mov x1, xzr
    mov x8, #101
    svc #0
    subs w12, w12, #1
    b.ne .Lwait_sibling
    b .Lfail
.Lsibling_ready:
    add x0, x19, #24
    mov x8, #96
    svc #0
    ldr w10, [x19, #20]
    cmp w0, w10
    b.ne .Lfail
    str w20, [x19]
    mov x0, #36
    b .Lexit
.Lexec:
    adr x0, missing
    adrp x1, argv
    add x1, x1, :lo12:argv
    add x2, x1, #16
    mov x8, #221
    svc #0
    cmn x0, #2
    b.ne .Lfail
    str w20, [x19]
    adr x0, program
    adrp x1, argv
    add x1, x1, :lo12:argv
    add x2, x1, #16
    mov x8, #221
    svc #0
.Lfail:
    mov x0, #99
    b .Lexit
.Lsibling:
    ldar w10, [x22]
    cbz w10, .Lsibling
    mov x8, #178
    svc #0
    cmp x0, #0
    b.le .Lfail
    mov w10, #2
    stlr w10, [x22]
    mov x0, xzr
    mov x8, #93
    svc #0
    brk #0
.Lnested:
    mov x0, #0x4111
    mov x1, xzr
    add x2, x19, #4
    mov x3, xzr
    mov x4, xzr
    mov x8, #220
    svc #0
    cbz x0, .Lgrandchild
    tbnz x0, #63, .Lfail
    mov x21, x0
    ldr w10, [x19]
    cmp w10, #3
    b.ne .Lfail
    add x1, x19, #8
    mov x2, xzr
    mov x3, xzr
    mov x8, #260
    svc #0
    cmp x0, x21
    b.ne .Lfail
    ldr w10, [x19, #8]
    mov w11, #0x2100
    cmp w10, w11
    b.ne .Lfail
    mov x0, xzr
    b .Lexit
.Lgrandchild:
    mov w10, #3
    str w10, [x19]
    mov x0, #33
    b .Lexit
.Lprint:
    mov x0, #1
    mov x8, #64
    svc #0
    mov x0, #0
.Lexit:
    mov x8, #94
    svc #0
    brk #0
.section .rodata
passed: .ascii "vfork-shared-exit-exec-ok\n"
passed_end:
missing: .asciz "/sucrune-vfork-does-not-exist"
program: .asciz "/usr/bin/hello"
greeting: .asciz "--greeting=vfork-hello"
.balign 8
delay: .quad 0, 50000000
.data
.balign 8
shared: .word 0, 0, 0, 0, 0, 0, 0, 0
argv: .quad program, greeting, 0
.bss
.balign 16
usage: .space 144
.space 16384
sibling_top:
.section .note.GNU-stack,"",%progbits
