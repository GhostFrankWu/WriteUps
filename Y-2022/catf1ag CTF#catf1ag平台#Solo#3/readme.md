# catf1ag CTF 两小时AK赛
## WEB - 签到了!!!你会玩2048么
找到js文件ctrl+f  
或者改本地缓存也可以
## MISC - 签签
文件尾放着flag的base64+ulencode
## MISC - 奇怪的字符
搜索引擎搜空白字符前边的文字，找到原题
```python
a = '''bcwb4g`slyLMb?ftR~qh'''
f = 1
for i in a:
    print(chr(ord(i)^f),end='')
    f +=1
```
## CRYPTO - 怎么会多一个呢
factordb找到分解，多个质数不影响求逆，用(p-1)*(q-1)*(r-1)求逆元即可
## CRYPTO - 高实在是高
搜RSA已知高位，抄weichujian师傅的脚本
## CRYPTO - 栓q
前半部分零宽身上纹，后半部分搜AT+CMGS decode找到能用的解码网站，或者直接从hex转
## WEB - easy_unser
反序列化，`$value="<?php system('cat /flag');"`，改长度计数跳过__wakeup()
## ATTACK - 查杀
`find / -name *.sh`找到shell和ip，或者ip也可以从log里找  
`find / -name *.php`找到php，都翻了一遍找了能执行的  
`cat /etc/passwd`找到所有用户
