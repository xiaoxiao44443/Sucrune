#if defined(__aarch64__)
.text
.global _start
.type _start,%function
_start:
    mov x0,#17
    mov x1,#0
    mov x2,#0
    mov x3,#0
    mov x4,#0
    mov x8,#220
    svc #0
    cbz x0,.Lchild
    tbnz x0,#63,.Lfailed
    mov x20,x0
    sub sp,sp,#16
    mov x1,sp
    mov x2,#0
    mov x3,#0
    mov x8,#260
    svc #0
    cmp x0,x20
    b.ne .Lfailed
    ldr w21,[sp]
    cbnz w21,.Lstatus
    mov x0,#1
    adr x1,.Lpass
    mov x2,#(.Lpass_end-.Lpass)
    mov x8,#64
    svc #0
    mov x0,#0
    b .Lexit
.Lchild:
    sub sp,sp,#48
    adr x1,.Lcustom_name
    adr x2,.Lgreeting
    stp x1,x2,[sp]
    str xzr,[sp,#16]
    adr x3,.Llocale
    stp x3,xzr,[sp,#24]
    adr x0,.Lmissing
    mov x1,sp
    add x2,sp,#24
    mov x8,#221
    svc #0
    cmn x0,#2
    b.ne .Lfailed
    adr x0,.Lreal
    mov x1,sp
    add x2,sp,#24
    mov x8,#221
    svc #0
    neg x0,x0
    b .Lexit
.Lstatus:
    lsr w0,w21,#8
    cbnz w0,.Lexit
.Lfailed:
    mov x0,#99
.Lexit:
    mov x8,#94
    svc #0
    brk #0
.Lmissing: .asciz "/sucrune-missing-child-executable"
.Lreal: .asciz "/usr/bin/hello"
.Lcustom_name: .asciz "fork-child-chosen-argv-zero"
.Lgreeting: .asciz "--greeting=exec-original-glibc-ok"
.Llocale: .asciz "LC_ALL=C"
.Lpass: .ascii "fork-exec-wait-ok\n"
.Lpass_end:
.section .note.GNU-stack,"",%progbits
#endif
