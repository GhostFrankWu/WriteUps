# XtraORdinary 15
>Check out my new, never-before-seen method of encryption! I totally invented it myself. I added so many for loops that I don't even know what it does. It's extraordinarily secure!

## Encrypt
加密由两部分构成：
```python
with open('flag.txt', 'rb') as f:
    flag = f.read()

with open('secret-key.txt', 'rb') as f:
    key = f.read()

def encrypt(ptxt, key):     #循环XOR，key未知
    ctxt = b''
    for i in range(len(ptxt)):
        a = ptxt[i]
        b = key[i % len(key)]
        ctxt += bytes([a ^ b])
    return ctxt

ctxt = encrypt(flag, key)   #得到第一次加密后的key
```
还有很fancy的第二轮：
```python
random_strs = [
    b'my encryption method',
    b'is absolutely impenetrable',
    b'and you will never',
    b'ever',
    b'ever',
    b'ever',
    b'ever',
    b'ever',
    b'ever',
    b'break it'
]

for random_str in random_strs:
    for i in range(randint(0, pow(2, 8))):
        for j in range(randint(0, pow(2, 6))):
            for k in range(randint(0, pow(2, 4))):
                for l in range(randint(0, pow(2, 2))):
                    for m in range(randint(0, pow(2, 0))):
                        ctxt = encrypt(ctxt, random_str)
```
对同一段文本，XOR 1、3、5、7、9...次的结果都是一样的  
上边代码等效于
```python
for random_str in random_strs:
    for i in range(randint(0, 1)):
        ctxt = encrypt(ctxt, random_str)
```
也就是说random_strs的每一个独立元素只会被XOR 0次或者1次  
所以第二段加密最多只能产生32种结果
```python
pow(2,len(set(random_strs))) = pow(2,5) = 32
```
## Decrypt
亦或回去就可以得到第一次加密后的32种可能的文本
```python
flag = bytes.fromhex("flag的密文")
prob = b'picoCTF{'
c=[]
for i in range(2):
    for j in range(2):
        for k in range(2):
            for l in range(2):
                for m in range(2):
                    c.append(flag)
                    flag = encrypt(flag, random_strs[0])
                flag = encrypt(flag, random_strs[1])
            flag = encrypt(flag, random_strs[2])
        flag = encrypt(flag, random_strs[3])
    flag = encrypt(flag, random_strs[4])
```
加密用的key是未知的，可能需要爆破。  
假设key的长度小于等于8，就可以先用'picoCTF{'[:len(key)]亦或上边的密文得到可能的key，这样用key解密的flag才是符合格式的，同时flag最后一位应该是'}'，故爆破：
```python
for i in c:
    for n in range(1, len(prob)):
        if encrypt(i, encrypt(prob[:n], i))[-1] == ord('}'):
            print(encrypt(i, encrypt(prob[:n], i)))
```
得到flag