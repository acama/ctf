;
;	assemble with nasm -o readfile.o -DFILENAME=\"somefile\" -DSIZE=0x<somesize>
;

USE64
DEFAULT REL

	section .data	; for testing
	global _start

%define BUF_SIZ 4096

filenm:
	db FILENAME
end:
	nop
; setup env
_start:
	xor rax, rax
	mov al, 0x10
	shl rax, 0x8
	sub rsp, rax	; rsp - 0x1000
	xor rbx, rbx
	xor rsi, rsi
	xor rcx, rcx
	mul rcx		; rdx:rax = 0
open:
	lea rdi, [filenm]
    mov rsi, 0x1000 ; O_RDONLY | O_DIRECTORY
	mov [end], cl	; put the null byte in place
	inc al
	inc al		; rax = 0x2
	syscall
    mov r9, rax

    mov r10, rsp
    sub r10, BUF_SIZ

getdirs:
    mov rdi, r9
    mov rsi, r10
    mov rdx, BUF_SIZ
    mov rax, 78
    syscall
    cmp rax, 0
    je exit
    mov r12, rax
    mov r13, 0

print_out:
    lea rsi, [r10 + r13 + 0x12]
    call puts
    lea r8, [r10 + r13 + 0x10]         ; d_reclen
    movzx r8, word [r8]
    add r13, r8
    cmp r13, r12
    jge getdirs
    jmp print_out

puts:
	xor rdi, rdi
	inc rdi
    mov rdx, 1
	xor rax, rax	
	inc rax
	syscall
    inc rsi
    cmp byte [rsi], 0
    jne puts
nl:
    mov byte [rsi], 0xa
	xor rdi, rdi
	inc rdi
    mov rdx, 1
	xor rax, rax	
	inc rax
	syscall
    ret
    
exit:
	xor rax, rax
	mov al, 60
	syscall
