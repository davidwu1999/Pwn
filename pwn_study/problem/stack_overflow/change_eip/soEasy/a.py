# a=[
# "35cd2d0c8b1ac9790689eb0b82c97913",
# "dd8874cd2da8729f05b80e6568434f65",
# "97bdb0a8f6cf2d684367608f46656803",
# "4665689b22877946656843b705f60e9a",
# "4031468d2d842f403146658806a00831",
# "9122863b9720ae25b705f746952d8567",
# "b32d856f95748078bc06a14be203a36f",
# "eb03a3349a22862e9e20ae7bb005f717",
# "b905f74cb82d85579c74805db306a154",
# "8a06a119d003a351a32286199920ae59",
# "a020ae618205f762812d8543a3748069",
# "aa7480168106a15ed903a377a4228630",
# "ad228634ab20ae4b8b05f77c8e2d857a",
# "b3e10bb705bc0ead3dc82f4ade03a37d",
# "f1f06aa8d76880b4b99a9f918f87b80e",
# "8f45454665686b424c020e01900eec08",
# "c748e87d8948e5894855c3f846614ef5"
# ]
# for i in a:
# 	print i.decode('hex')[::-1].encode('hex')
f=open('./x','rb')
f2=open('./dump','wb')
rd=f.read()
for i in xrange(0,len(rd),7):
	f2.write(rd[i]^0x46)
	f2.write(rd[i]^0x31)
	f2.write(rd[i]^0x40)
	f2.write(rd[i]^0x67)
	f2.write(rd[i]^0x43)
	f2.write(rd[i]^0x68)
	f2.write(rd[i]^0x65)
f.close()
f2.close()