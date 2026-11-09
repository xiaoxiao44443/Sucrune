/* A freestanding Linux/AArch64 program: no Android or Sucrune symbols.
 * It uses only the Linux initial stack and write(64)/exit(93) ABI.
 * x18 and TPIDR_EL0 are deliberately untouched in this trusted fixture. */
.text
.global _start
.type _start, %function
_start:
    mov x20, sp
    and x9, x20, #15
    cbnz x9, bad_stack
    ldr x9, [sp]
    cmp x9, #1
    b.ne bad_args
    ldr x9, [sp, #8]
    cbz x9, bad_args
    ldrb w10, [x9]
    cmp w10, #'s'
    b.ne bad_args
    ldr x9, [sp, #16]
    cbnz x9, bad_args
    ldr x9, [sp, #24]
    cbz x9, bad_args
    ldrb w10, [x9]
    cmp w10, #'S'
    b.ne bad_args
    ldr x9, [sp, #32]
    cbnz x9, bad_args

    add x9, sp, #40
    mov x12, #0
    mov x13, #32
aux_loop:
    ldp x10, x11, [x9], #16
    cbz x10, aux_done
    cmp x10, #6 // AT_PAGESZ
    b.ne aux_entry
    cmp x11, #4096
    b.eq page_ok
    cmp x11, #16384
    b.ne bad_aux
page_ok:
    orr x12, x12, #1
aux_entry:
    cmp x10, #9 // AT_ENTRY
    b.ne aux_random
    adr x14, _start
    cmp x11, x14
    b.ne bad_aux
    orr x12, x12, #2
aux_random:
    cmp x10, #25 // AT_RANDOM
    b.ne aux_next
    cbz x11, bad_aux
    ldr x14, [x11] // Verify that the 16-byte random area is readable.
    ldr x14, [x11, #8]
    orr x12, x12, #4
aux_next:
    subs x13, x13, #1
    b.ne aux_loop
    b bad_aux
aux_done:
    cmp x12, #7
    b.ne bad_aux

    adr x9, zero_area
    mov x10, #8
bss_loop:
    ldr x11, [x9], #8
    cbnz x11, bad_bss
    subs x10, x10, #1
    b.ne bss_loop
    adr x9, zero_area
    mov x10, #90
    str x10, [x9]
    ldr x11, [x9]
    cmp x10, x11
    b.ne bad_bss
    adr x9, initialized_data
    ldr x10, [x9]
    cmp x10, #123
    b.ne bad_data
    add x10, x10, #1
    str x10, [x9]
    ldr x11, [x9]
    cmp x11, #124
    b.ne bad_data

    mov x0, #1
    adr x1, hello
    mov x2, #(hello_end - hello)
    mov x8, #64
    svc #0
    cmp x0, #(hello_end - hello)
    b.ne bad_write
    mov x0, #42
    b finish
bad_stack: mov x0, #70; b finish
bad_args: mov x0, #71; b finish
bad_aux: mov x0, #72; b finish
bad_bss: mov x0, #73; b finish
bad_data: mov x0, #74; b finish
bad_write: mov x0, #75
finish:
    mov x8, #93
    svc #0
    b . // Linux exit must never return.
.size _start, .-_start
.section .rodata
hello: .ascii "Hello from Sucrune ELF!\n"
hello_end:
.data
.balign 8
initialized_data: .quad 123
.bss
.balign 16
zero_area: .skip 64
.section .note.GNU-stack,"",%progbits
