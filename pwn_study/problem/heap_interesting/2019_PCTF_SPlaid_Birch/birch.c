from pwn import *

p = process('./splaid-birch')
context.log_level='debug'

def delete(index):
	p.sendline('1')
	p.sendline(str(index))

def view(index):
	p.sendline('2')
	p.sendline(str(index))
	return p.recvline()

def nth(index):
	p.sendline('3')
	p.sendline(str(index))
	return p.recvline()

def select(index):
	p.sendline('4')
	p.sendline(str(index))
	return p.recvline()

def set(index, value):
	p.sendline('5')
	p.sendline(str(index))
	p.sendline(str(value))
	
'''
set(0, 1)
set(1, 2)
set(2, 3)
print view(0)
print view(1)
print view(2)
delete(0)
'''
