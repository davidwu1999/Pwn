from pwn import *
import sys
import requests
import os

headers = {
"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
"Cookie": "JSESSIONID=2C143ED27716BBF535C7E18A59531DE0",
"Host": "172.91.1.12:9090",
"Origin": "http://172.91.1.12:9090",
"Referer": "http://172.91.1.12:9090/arace/index",
"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36",
"X-Requested-With": "XMLHttpRequest",
}
def submitflag(flag):
	data = {"flag":flag}
	r = requests.post("http://172.91.1.12:9090/ad/hacker/submit/submitCode",headers=headers,data=data)
	print r.content

a="311af03a5fb802e845bb26571c18c787f7e04d50cec55d5d9325ce22bd91628cedbbfe07488049c1fa837e8f869ccbbfadf9fc2f9c7900c7981f4f51c14c295dab9a04f42301366b2f792b31f3b9030adbc2173beb41524e37c8c1028e54abe5"
submitflag(a)
"""
for i in range(50):
	try:
		ip = "192.168.1.{ip}".format(ip=i)
		os.system("python shotshot.py {ip} {port}".format(ip=ip,port=9983))
	except KeyboardInterrupt:
		break
	except:
		continue
"""
