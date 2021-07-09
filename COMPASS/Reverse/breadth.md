# breadth 20
> Surely this is what people mean when they say "horizontal scaling," right?  
TOP SECRET INFO:  
Our operatives managed to exfiltrate an in-development version of this challenge, where the function with the real flag had a mistake in it. Can you help us get the flag?

# Explore
ida发现有上万个输出flag的函数，把函数名全选复制出来，存到了1.txt和2.txt里，改成pdb的语句，里边的内容大概是这样
>p (long)fcntgwxYD()  
>p (long)fcnasfuTQ()  
>p (long)fcnuaswPS()  
>...

打开pdb，因为程序会直接执行结束，所以在main下断点，之后导入并执行全部函数的脚本程序"1.py":
```python
import sys
import gdb
import os

def d():
  f=open("/your_path/1.txt","r")
  k=open("/your_path/1r.txt","w")
  for i in f.readlines():
  	i=i.replace("void","long")
  	s=gdb.execute(i,False, True)
  	k.write(s)
  f.close()
  k.close()
```
gdb命令：
>b main  
>r  
>source -v 1.py  
>python d()  

程序运行到一半就把flag打印出来了