#if defined(__aarch64__)
.text
.global _start
.type _start,%function
_start:
    adrp x20, .Lmemory
    add x20, x20, :lo12:.Lmemory
    msr tpidr_el0, x20
    mov x18, #0x1234
    movi v23.16b, #0x5a
    mov x8, #172
    svc #0
    str w0, [x20, #12]
    mov x0, #17
    movk x0, #0x0120, lsl #16 // CHILD_SETTID | CHILD_CLEARTID | SIGCHLD
    mov x1, #0
    mov x2, #0
    mov x3, #0
    add x4, x20, #4
    mov x8, #220
    svc #0
    cbz x0, .Lchild
    tbnz x0, #63, .Lparent_fail
    mov x21, x0
    add x1, x20, #8
    mov x2, #0
    mov x3, #0
    mov x8, #260
    svc #0
    cmp x0, x21
    b.ne .Lparent_fail
    ldr w9, [x20, #8]
    mov w10, #0x2900
    cmp w9, w10
    b.ne .Lparent_fail
    ldr w9, [x20]
    cmp w9, #7
    b.ne .Lparent_fail
    ldr w9, [x20, #4]
    cbnz w9, .Lparent_fail
    mov x0, #1
    adr x1, .Lpass
    mov x2, #(.Lpass_end-.Lpass)
    mov x8, #64
    svc #0
    mov x0, #0
    b .Lexit
.Lchild:
    mrs x9, tpidr_el0
    cmp x9, x20
    b.ne .Lchild_fail
    mov x10, #0x1234
    cmp x18, x10
    b.ne .Lchild_fail
    movi v1.16b, #0x5a
    cmeq v1.16b, v1.16b, v23.16b
    uminv b1, v1.16b
    umov w10, v1.b[0]
    cmp w10, #255
    b.ne .Lchild_fail
    mov x8, #172
    svc #0
    ldr w10, [x20, #4]
    cmp w0, w10
    b.ne .Lchild_fail
    mov x8, #173
    svc #0
    ldr w10, [x20, #12]
    cmp w0, w10
    b.ne .Lchild_fail
    mov w9, #99
    str w9, [x20]
    mov x0, #1
    adr x1, .Lchild_line
    mov x2, #(.Lchild_end-.Lchild_line)
    mov x8, #64
    svc #0
    cmp x0, #(.Lchild_end-.Lchild_line)
    b.ne .Lchild_fail
    mov x0, #41
    b .Lexit
.Lchild_fail:
    mov x0, #77
    b .Lexit
.Lparent_fail:
    mov x0, #78
.Lexit:
    mov x8, #94
    svc #0
    brk #0
.Lchild_line: .ascii "fork-child\n"
.Lchild_end:
.Lpass: .ascii "fork-cow-tls-fpsimd-wait-ok\n"
.Lpass_end:
.data
.balign 16
.Lmemory: .word 7,0,0,0
.section .note.GNU-stack,"",%progbits
#endif
