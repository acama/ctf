/*
	assemble with as sh.asm -o sh.o
	get raw binary with objcopy -O binary sh.o sh.bin
*/

	.text
	.global _start

_start:

read_sc:
	ldr r1, =#0x4700000
	mov r2, #0x22000
	mov r0, #0
	swi 0x0

exec_sc:
	ldr r1, =#0x4700000 
	mov r2, #0x22000
	mov r0, #3
	swi 0x0
