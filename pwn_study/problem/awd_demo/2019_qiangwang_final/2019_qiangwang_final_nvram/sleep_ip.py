import os
import time

while True:
	for i in range(1,27):
		ip = "172.29.{ip}.14".format(ip = str(i))
		port = 20004
		try:
			os.system("python ./nvram.py {ip} {port}".format(ip = ip,port = port))
		except keyboardexception:
			break
		except:
			pass
	time.sleep(5)
