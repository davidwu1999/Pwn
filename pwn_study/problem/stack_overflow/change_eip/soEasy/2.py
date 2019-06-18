# import dis
# strsx=[
# "6400006401006c00005a00006400006402006c01006d02005a0200016400",
# "006401006c03005a03006400006401006c04005a04006403005a05006404",
# "008400005a06006405008400005a07006506006505006406002083010065",
# "070065050064060064070021830100176506006505006407001f83010017",
# "5a08006500006a090065080083010047486408005a080064010053"
# ]
# strs=[
# "6401006a00007401006a02007403006a04006402008302008301007d01006401007d02007846007405007406007c0000830100830100445d32007d03007c02007407007408007c00007c0300198301007408007c01007c0300640200161983010041830100377d0200713700577c020053",
# "6401007d02007846007405007406007c0000830100830100445d32007d03",
# "007c02007407007408007c00007c0300198301007408007c01007c030064",
# "0200161983010041830100377d0200713700577c020053"
# ]
# strs=[
# "7400008300007d01007c01006a01007c0000830100017c01006a020083000053",
# ""
# ]
# strs=[
# "6400006401006c000054650100650200640200830100830100474864030053",
# "53"
# ]
# stra=""
# for i in strsx:
# 	stra+=i
# code = stra.decode('hex')
# print dis.disassemble_string(code)

# from base64 import *
# strs=b64decode('U1VQU05pSHdqCEJrQu7FS7Vngk1OTQ58qqghXmt2AUdrcFBBUEU=')+'\x00\x00'
# print len(strs)
# print hex(ord(strs[0])^ord('f'))
# print hex(ord(strs[1])^ord('l'))
# print hex(ord(strs[2])^ord('a'))
# print hex(ord(strs[3])^ord('g'))
# print hex(ord(strs[4])^ord('{'))
# print hex(ord(strs[37])^ord('}'))
# print strs[12:28].encode('hex')

# for x in xrange(0x38,0x3a):
# 	for y in xrange(0x31,0x3a):
# 		for j in xrange(0x30,0x38):
# 			for i in xrange(28,len(strs),4):
# 				print chr(ord(strs[i])^x),
# 				print chr(ord(strs[i+1])^0x38),
# 				print chr(ord(strs[i+2])^y),
# 				print chr(ord(strs[i+3])^j),
# 			print hex(x),hex(y),hex(j)

# import random
# import string

# while True:
# 	__=''.join(random.sample(string.digits,4))
# 	if __=="5914":
# 		print ''.join(random.sample(string.digits,4))
# 		print ''.join(random.sample(string.digits,4))
# 		exit()
#0697
#6391
# from md5 import *
# ___ = md5()
# ___.update('1')
# print  len(___.digest())

#print hex(0x7f8cbbde2b78-0x7f8cbba1e000)
print 'aaa'.ljust(12,'b')