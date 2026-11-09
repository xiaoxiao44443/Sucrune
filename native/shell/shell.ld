ENTRY(_start)
PHDRS {
    text PT_LOAD FILEHDR PHDRS FLAGS(5);
    data PT_LOAD FLAGS(6);
    stack PT_GNU_STACK FLAGS(6);
}
SECTIONS {
    . = SIZEOF_HEADERS;
    .text : { *(.text*) } :text
    .rodata : { *(.rodata*) } :text
    . = ALIGN(0x4000);
    .data : { *(.data*) *(.got*) *(.data.rel.ro*) } :data
    .bss (NOLOAD) : { *(.bss*) *(COMMON) } :data
    .rela.dyn : { *(.rela*) *(.rel*) } :data
    ASSERT(SIZEOF(.rela.dyn) == 0, "Sucrune shell must not need dynamic relocations")
    /DISCARD/ : { *(.dynamic) *(.dynsym) *(.dynstr) *(.hash) *(.gnu.hash) *(.comment) *(.note*) *(.eh_frame*) }
}
