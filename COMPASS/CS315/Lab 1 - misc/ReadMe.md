# 1 What is so called stream?

筛选 udp.stream eq 6 逐个读出flag

# 2 HTTPS with secret sauce

百度wireShark解密https，根据教程配置TLS密钥，指定下载的log后重启wireshark。   
导出所有解析结果为json，根据提示搜索 y2 得到flag

# 3 Bytes through network
>That hacker still got my flag! Fine, I'm going to send my file byte by byte. Besides, combined with my knowledge of programming, encryption, and stenography I'm going to fight the final round. WE ARE IN THE ENDGAME NOW.
>
>capture.pcapng
>
>Try to find flag in this file, the flag format is: flag{***}
>
>This challenge is extremely hard. The winner will get a badge for solving this.

## 流量包分析
附件一个流量包，打开发现是tcp包装的http，筛选所有http分组导出解析结果为1.json。   
发现传输逻辑是每个端口建立一个连接，请求一个字节，然后接收这个字节，写脚本恢复文件：
```python
import json
import os

d=json.load(open("1.json","r",encoding="utf8"))
ports={} # 记录当前端口传输的是第几个字节
send=["\xff"]*1987 # bytes= 一共出现了1987次

for i in range(0,len(d)):
    if 'http.request.line' in d[i]['_source']['layers']['http'].keys() and "bytes=" in d[i]['_source']['layers']['http']['http.request.line']:
        port=d[i]['_source']['layers']['tcp']['tcp.srcport']
        ports[port]=d[i]['_source']['layers']['http']['http.request.line'].split("bytes=")[1].split("-")[0]
    elif 'data' in d[i]['_source']['layers'] and d[i]['_source']['layers']['data']['data.len']=='1':
        port=d[i]['_source']['layers']['tcp']['tcp.dstport']
        send[int(ports[port])]=bytes.fromhex(d[i]['_source']['layers']['data']['data.data'])
        del ports[port] # remove有回显，del没有
    else:
        print(bytes.fromhex(d[i]['_source']['layers']['tcp']['tcp.payload'].replace(":","")))

f=open("1.bin","wb")
for i in range(0,1987):
    f.write(send[i])

f.close()
```

## pyc反编译
分析文件发现很多python的方法名以及"main.py", 推测是pyc文件，magic number找不到是哪个python版本(学姐说是3.10b2，但是不影响后续解题)。  

发现pycdc在线工具https://tool.lu/pyc/ 不能反编译得到的pyc文件，本地也不能运行，magic number不属于3.9及之前的任何一个版本。  
本机随便编译一个python3.9的程序，把文件前12个字节复制进去就可以反编译部分，得到初步反编译的文件

>.~/pycdc-master$ ./pycdc 1.pyc

```python
# Source Generated with Decompyle++
# File: 1 - 副本.pyc (Python 3.9)

import sys
from hashlib import sha256

def KSA(key):
    keylength = len(key)
    S = list(range(256))
    j = 0
    return S


def PRGA(S):
Unsupported opcode: <255>
    pass
# WARNING: Decompyle incomplete


def RC4(key):
    S = KSA(key)
    return PRGA(S)


def xor(p, stream):
    return None(None((lambda x = None: x ^ stream.__next__()), p))

if __name__ == '__main__':
    w = b'\xf6\xef\x10H\xa9\x0f\x9f\xb5\x80\xc1xd\xae\xd3\x03\xb2\x84\xc2\xb4\x0e\xc8\xf3<\x151\x19\n\x8f'
    e = b'$\r9\xa3\x18\xddW\xc9\x97\xf3\xa7\xa8R~'
    b = b'geo'
    s = b'}\xce`\xbej\xa2\x120\xb5\x8a\x94\x14{\xa3\x86\xc8\xc7\x01\x98\xa3_\x91\xd8\x82T*V\xab\xe0\xa1\x141'
    t = b"Q_\xe2\xf8\x8c\x11M}'<@\xceT\xf6?_m\xa4\xf8\xb4\xea\xca\xc7:\xb9\xe6\x06\x8b\xeb\xfabH\x85xJ3$\xdd\xde\xb6\xdc\xa0\xb8b\x961\xb7\x13=\x17\x13\xb1"
    m = {
        2: 115,
        8: 97,
        11: 117,
        10: 114 }
    n = {
        3: 119,
        7: 116,
        9: 124,
        12: 127 }
Unsupported opcode: MAP_ADD
    m |= (lambda .0: pass# WARNING: Decompyle incomplete
)(n)
Unsupported opcode: <255>
    m |= (lambda .0: pass# WARNING: Decompyle incomplete
)(b)
    stream = RC4(list(map((lambda x: x[1]), sorted(m.items()))))
    print(xor(w, stream).decode())
    p = sys.stdin.buffer.read()
    e = xor(e, stream)
    c = xor(p, stream)
    if sha256(c).digest() == s:
        print(xor(t, stream).decode())
        return None
    None(e.decode())
    return None
```
## 字节码分析修复
残缺很大一部分，还有些意义不明的lambda表达式，对照反编译的字节码分析：
>.~/pycdc-master$ ./pycdas 1.pyc

```python
    m |= (lambda .0: pass# WARNING: Decompyle incomplete
)(n)
Unsupported opcode: <255>
    m |= (lambda .0: pass# WARNING: Decompyle incomplete
)(b)
# 上边对应的字节码是下边的内容
106     STORE_NAME              14: n
108     LOAD_NAME               13: m
110     LOAD_CONST              27: <CODE> <dictcomp>
112     LOAD_CONST              28: '<dictcomp>'
114     MAKE_FUNCTION           0
116     LOAD_NAME               14: n
118     GET_ITER
120     CALL_FUNCTION           1
122     INPLACE_OR
124     STORE_NAME              13: m
126     LOAD_NAME               13: m
128     LOAD_CONST              29: <CODE> <genexpr>
130     LOAD_CONST              30: '<genexpr>'
132     MAKE_FUNCTION           0
134     LOAD_NAME               10: b
136     GET_ITER
138     CALL_FUNCTION           1
```
dictcomp百度释义为字典推导，大致意为字典key键与值value之间的运算，分析dictcomp的字节码：
```python
[Code]
    File Name: main.py
    Object Name: <dictcomp>
    Arg Count: 1
    Pos Only Arg Count: 0
    KW Only Arg Count: 0
    Locals: 2
    Stack Size: 6
    Flags: 0x00000043 (CO_OPTIMIZED | CO_NEWLOCALS | CO_NOFREE)
    [Names]
        'n'
    [Var Names]
        '.0'
        'x'
    [Free Vars]
    [Cell Vars]
    [Constants]
    [Disassembly]
        0       BUILD_MAP               0
        2       LOAD_FAST               0: .0
        4       FOR_ITER                9 (to 15)
        6       STORE_FAST              1: x
        8       LOAD_FAST               1: x
        10      LOAD_FAST               1: x
        12      LOAD_GLOBAL             0: n
        14      LOAD_FAST               1: x
        16      BINARY_SUBSCR
        18      BINARY_XOR
        20      MAP_ADD                 2
        22      JUMP_ABSOLUTE           2
        24      RETURN_VALUE
'<dictcomp>'
```
推测为字典的key与value进行XOR，对n运算,与m|=运算得到
```python
m = {
        2: 115,
        3: 116,
        7: 115,
        8: 97,
        9: 117,
        10: 114,
        11: 117,
        12: 115 } # st***saurus
```
同理分析genexpr迭代表达式的字节码，排序依据是bit_count,geo按字典序或者ASCII的大小排是ego，组成stegosaurus，隐写蜥蜴（剑龙）。  
修改pyc反汇编的py代码，网上找一个能用的RC4加密板子改一下，得到手动修复后的代码
```python
from hashlib import sha256


def RC4(texts, key):
    results = [''] * len(texts)
    key_len = len(key)  # 1. init S-box
    box = list(range(256))  # put 0-255 into S-box
    j = 0
    for i in range(256):  # shuffle elements in S-box according to key
        j = (j + box[i] + (key[i % key_len])) % 256
        box[i], box[j] = box[j], box[i]  # swap elements
    i = j = 0  # 2. make sure all elements in S-box swapped at least once
    for m in range(0, len(texts)):
        text = texts[m]
        result = ''
        for element in text:
            i = (i + 1) % 256
            j = (j + box[i]) % 256
            box[i], box[j] = box[j], box[i]
            k = chr(element ^ box[(box[i] + box[j]) % 256])
            result += k
        results[m] = result
    return results


if __name__ == '__main__':
    w = b'\xf6\xef\x10H\xa9\x0f\x9f\xb5\x80\xc1xd\xae\xd3\x03\xb2\x84\xc2\xb4\x0e\xc8\xf3<\x151\x19\n\x8f'
    e = b'$\r9\xa3\x18\xddW\xc9\x97\xf3\xa7\xa8R~'
    b = b'geo'
    s = b'}\xce`\xbej\xa2\x120\xb5\x8a\x94\x14{\xa3\x86\xc8\xc7\x01\x98\xa3_\x91\xd8\x82T*V\xab\xe0\xa1\x141'
    t = b"Q_\xe2\xf8\x8c\x11M}'<@\xceT\xf6?_m\xa4\xf8\xb4\xea\xca\xc7:\xb9\xe6\x06\x8b\xeb\xfabH\x85xJ3$\xdd\xde\xb6" \
        b"\xdc\xa0\xb8b\x961\xb7\x13=\x17\x13\xb1 "
    m = {2: 115,
         3: 116,
         4: 101,
         5: 103,
         6: 111,
         7: 115,
         8: 97,
         9: 117,
         10: 114,
         11: 117,
         12: 115}  # "stegosaurus"
    p = b'a'*26 # 爆破个数即可，RC4密钥流在256内是唯一迭代，0-256之间如果
    # 长度不等于这一部分密文的长度，后续内容都会解密失败。爆破得到长度为26
    w, e, c, t = (RC4((w, e, p, t), list(map(lambda x: x[1], sorted(m.items())))))
    print(w.encode('utf-8'))  # b'Give me the mystery string :'
    print(c.encode('utf-8'))  # flag
    if sha256(c.encode('utf-8')).digest() == s:
        print(t.encode('utf-8'))  # b'Congratulations! Now you should now what the flag is\x11'
    else:
        print(e.encode('utf-8'))  # b'You are wrong!'

```
## 修改隐写解密脚本
和固定序列XOR得到flag的过程无法爆破，考虑提示的隐写  
stegosaurus是一个pyc隐写脚本，github搜索stegosaurus第一条就可以找到脚本仓库https://github.com/AngelKitty/stegosaurus ，但是尝试解密时会报错
>    code = marshal.load(f)  
>ValueError: bad marshal data (unknown type code)

定位到出错点
```python
def _loadBytecode(carrier, logger):
    try:
        f = open(carrier, "rb")
        header = f.read(8) # 报错
        code = marshal.load(f)
        logger.debug("Read header and bytecode from carrier")
    finally:
        f.close()

    return (header, code)
```
在尝试用dis反汇编这个pyc的时候发现这个pyc头长度不是8而是12，因此将这里的预读也改成12，可以正确解密，但是输出报错：
>    payload = bytearray(payloadBytes, "utf8")  
>TypeError: encoding without a string argument

定位到出错点
```python
def _extractPayload(mutableBytecodeStack, explodeAfter, logger):
    payloadBytes = bytearray()

    for bytes, byteIndex in _bytesAvailableForPayload(mutableBytecodeStack, explodeAfter):
        byte = bytes[byteIndex]
        if byte == 0:
            break
        payloadBytes.append(byte)

    payload = bytearray(payloadBytes, "utf8") # 报错

    print("Extracted payload: {}".format(payload))
```

stegosauruss声称自己可以加密非ASCII字符，但是这里尝试解码非ASCII，让他直接以编码状态输出，去掉 [*, "utf8"*],得到输出
>Extracted payload: bytearray(b'\xe5\n2\xd6"\xf0}I\xb0\xcd\xa2\x11\xf0\xb4U\x166\xc5o\xdb\xc9\xead\x04\x15b')

## 解密flag<!--  -->
补全修复的python代码的密钥，得到解密脚本
```python
from hashlib import sha256


def RC4(texts, key):
    results = [''] * len(texts)
    key_len = len(key)  # 1. init S-box
    box = list(range(256))  # put 0-255 into S-box
    j = 0
    for i in range(256):  # shuffle elements in S-box according to key
        j = (j + box[i] + (key[i % key_len])) % 256
        box[i], box[j] = box[j], box[i]  # swap elements
    i = j = 0  # 2. make sure all elements in S-box swapped at least once
    for m in range(0, len(texts)):
        text = texts[m]
        result = ''
        for element in text:
            i = (i + 1) % 256
            j = (j + box[i]) % 256
            box[i], box[j] = box[j], box[i]
            k = chr(element ^ box[(box[i] + box[j]) % 256])
            result += k
        results[m] = result
    return results


if __name__ == '__main__':
    w = b'\xf6\xef\x10H\xa9\x0f\x9f\xb5\x80\xc1xd\xae\xd3\x03\xb2\x84\xc2\xb4\x0e\xc8\xf3<\x151\x19\n\x8f'
    e = b'$\r9\xa3\x18\xddW\xc9\x97\xf3\xa7\xa8R~'
    b = b'geo'
    s = b'}\xce`\xbej\xa2\x120\xb5\x8a\x94\x14{\xa3\x86\xc8\xc7\x01\x98\xa3_\x91\xd8\x82T*V\xab\xe0\xa1\x141'
    t = b"Q_\xe2\xf8\x8c\x11M}'<@\xceT\xf6?_m\xa4\xf8\xb4\xea\xca\xc7:\xb9\xe6\x06\x8b\xeb\xfabH\x85xJ3$\xdd\xde\xb6" \
        b"\xdc\xa0\xb8b\x961\xb7\x13=\x17\x13\xb1 "
    m = {2: 115,
         3: 116,
         4: 101,
         5: 103,
         6: 111,
         7: 115,
         8: 97,
         9: 117,
         10: 114,
         11: 117,
         12: 115}  # "stegosaurus"
    p = b'\xe5\n2\xd6"\xf0}I\xb0\xcd\xa2\x11\xf0\xb4U\x166\xc5o\xdb\xc9\xead\x04\x15b'
    w, e, c, t = (RC4((w, e, p, t), list(map(lambda x: x[1], sorted(m.items())))))
    print(w.encode('utf-8'))  # b'Give me the mystery string :'
    print(c.encode('utf-8'))  # flag
    if sha256(c.encode('utf-8')).digest() == s:
        print(t.encode('utf-8'))  # b'Congratulations! Now you should now what the flag is\x11'
    else:
        print(e.encode('utf-8'))  # b'You are wrong!'
```
执行得到正确的flag。