# re1
ida逆向，发现验证逻辑是非常长的一块。   
这道题需要“大胆推测”加密逻辑是每个byte之间不相关的（也可以把ida的配置文件调大一些反汇编看看）   
于是有两个思路：  
- patch掉错误判断的jnz，换成jz，逐位运行得到非win爆破出flag
- gdb动态调试得到验证逻辑最后的每一位输入。  
  
下边是第二种方式的脚本
注：
- d为验证函数最后比对用的数组
- gdb动态调试带ASLR的程序默认基址为0x555555400000
```python
from pwn import *
from time import sleep

p = process(['gdb', 'main'])
p.sendline(b"b *0x0000555555418096")
strs = b"0123456789abcdefghijklmnopqrstuvwxyz"
d = [0xEB, 0xF1, 25, 0xE8, 30, 30, 0xF0, 0xEC, 0xEF, 30, 0xE9, 30, 0xEC, 0xEC, 0xE8, 0xEC, 25, 25, 0xEE, 27, 0xEF, 0xEF,
     0xEC, 0xEA, 28, 0xEA, 0xE8, 0xEB, 0xEE, 0xEB, 29, 0xF1]
flag="flag{"

for i in range(0, 32):
    for j in strs:
        p.sendline(b"r")
        sleep(0.1)
        p.sendline(b"flag{0123456789abcdefghijklnmopqrstuv}")
        sleep(0.1)
        p.sendline(b'set $i="' + struct.pack("B", j) * 32 + b'"')
        sleep(0.1)
        p.sendline(b"p (void *)0x555555400810($i,32)")
        sleep(0.1)
        sa = p.clean()
        p.sendline(b"p (char)*($rdi+"+str(2*i).encode()+b")")
        sleep(0.1)
        s = str(p.recvline()).split(" = ")[1].replace("\\n'", "\n")
        print(s)
        s = int(s[2:], 16)
        if s == d[i]:
            flag += chr(j)
            break

print(flag+"}")
```
运行得到flag  
事实上，解密逻辑不仅char不相关，甚至32个flag每一位的加解密过程都是一样的，所以也可以通过爆第一位的字典拿到flag