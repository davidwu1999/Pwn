import struct

for i in xrange(0x7fffffffffffffff):
	info = struct.pack("<q",-i)
	res = struct.unpack("<Q",info)[0]
	if res == 0x200:
		print i
