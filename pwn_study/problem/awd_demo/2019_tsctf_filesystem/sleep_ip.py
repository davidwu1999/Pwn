import os
import time

while True:
	for i in range(1,18):
		ip = "172.16.20.{ip}".format(ip = str(i))
		port = 2968
		try:
			os.system("python ./filesystem.py {ip} {port}".format(ip = ip,port = port))
		except keyboardexception:
			break
		except:
			pass
	time.sleep(5)
