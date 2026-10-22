ENTRY(_start)

SECTIONS
{
    . = 0x10000;
    .text   : { *(.text.start) *(.text .text.*) }
    . = ALIGN(0x1000);
    .rodata : { *(.rodata .rodata.* .srodata .srodata.*) }
    .data   : { *(.data .data.* .sdata .sdata.*) }
    .bss    : { *(.bss .bss.* .sbss .sbss.* COMMON) }
    /* the stack: STACK_SIZE bytes (rules.mk, default 1024); its words are part of the proven
       RAM image, so a guest that needs little stack should set less */
    .stack (NOLOAD) : {
        . = ALIGN(16);
        __stack_bottom = .;
        . += DEFINED(__stack_size) ? __stack_size : 1024;
        __stack_top = .;
    }
}
