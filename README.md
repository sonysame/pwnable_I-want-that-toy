### pwnable_I-want-that-toy

There is a *Format String Bug* vulnerability in function *route*. If we send a HTTP request with User-Agent Header, the value of User-Agent is printed out. However, if we give format string as an User-Agent Header, memory near $rsp at that moment can be leaked(code, libc, stack, canary all can be leaked)

![](https://user-images.githubusercontent.com/24853452/52425685-db148580-2b3f-11e9-9fa5-86ef726bf339.png)

Also, if we give long length of input to toy, stack smashed error happens. Therefore, stack buffer overflow can occur and there is a canary! By using fsb above, we can know canary. Also by using stack overflow, we can overwrite return address.

We need to redirect stdin and stdout to the socket.  
We need dup2(4,0) dup2(4,1)

By using ROP with useful gadgets, we will execute these commands.  
 
    dup2(4,0), dup2(4, 1), system("/bin/sh\x00")

#### Gadget1 
![](https://user-images.githubusercontent.com/24853452/52426692-c6d18800-2b41-11e9-9f90-b3d3c03b88b5.png)

for first argument(rdi) 

#### Gadget2
![](https://user-images.githubusercontent.com/24853452/52426708-d2bd4a00-2b41-11e9-92ea-25636c0b096d.png)

for second argument(rsi)