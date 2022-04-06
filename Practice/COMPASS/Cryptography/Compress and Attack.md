# Compress and Attack 15
>Your goal is to find the flag. compress_and_attack.py nc mercury.picoctf.net 29350

# Explore
Salsa20流加密并不会影响加密文本的长度。
而zlib压缩会压缩重复长度的文本,比如：
>\>\>\>len(compress("picoCTF{1_am_A_student_age_24_abcdef}"))  
45
\>\>\>len(compress("picoCTF{1_am_A_student_age_24_abcdef}picoCTFpico"))  
48
\>\>\>len(compress("picoCTF{1_am_A_student_age_24_abcdef}picoCTFpicoCTF{"))  
48
因此只需要遍历字符，长度没有变化的返回就是正确的字符

# DeCrypt
写脚本遍历
```python
from pwn import *
import string

s = "picoCTF{"
p = remote("mercury.picoctf.net", 29350)
d = string.printable
while True:
    try:
        #d = "abcdefghijklmnopqrstuvwxyz_}"
        for i in d:
            p.sendline(s + i)
            p.recvline()
            p.recvline()
            l = int(p.recvline())
            print(s + i)
            print(l)
            if l == 48:
                s += i
                if i == '}':
                    exit(0)
                break
    except:
        p = remote("mercury.picoctf.net", 29350)
```
得到flag