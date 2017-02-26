ENTRY(_start)
SECTIONS
{
 . = 0x4400000;
 .text : {
 *(.text .rodata)
 }
 .data : { *(.data) }
 __bss_start__ = .;
 .bss : { *(.bss) }
 __bss_end__ = .;
 . = 0x6400000;
 heap_low = .; /* 2 MB of heap */
 . = . + 0x800000;
 heap_top = .;
}
