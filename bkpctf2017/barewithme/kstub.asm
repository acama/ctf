// Stub used to overwrite the 
// exception vector table
.globl _start
.CODE 32
_start:
    add r6, pc, #1
    bx r6
.CODE 16
thmb:
    ldr r1, =0xa00410   // address of kpayload.asm
    ldr r0, [r1, #0x38]
    ldr r2, [r1, #0x40]
    ldr r4, [r1, #0x3c]
    blx r4              // memcpy
    mov r6, r0
    bx r6

hang:
    b hang
