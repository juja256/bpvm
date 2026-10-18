ENTRY(_start)

SECTIONS
{
    . = 0x10000;
    .text   : { *(.text.start) *(.text .text.*) }
    . = ALIGN(0x1000);
    .rodata : { *(.rodata .rodata.* .srodata .srodata.*) }
    .data   : { *(.data .data.* .sdata .sdata.*) }
    .bss    : { *(.bss .bss.* .sbss .sbss.* COMMON) }
    .stack (NOLOAD) : {
        . = ALIGN(16);
        . += 16384;
        __stack_top = .;
    }
}
