# 1 Sanity Check
**Frank becomes so sad because there's ALL difficult challenges this week.**  
根据积累和特征，我们得出本题的flag：  
- flag{1_l0v3_54n17y_ch3ck_ch4ll5}  


# 2 VidCap
根据积累和特征，我们得出本题的前半段flag：  
- COMPFEST13{aha_gotcha_  

本周主题是OSINT，依据题目给出的hint，GayHub搜索出处《COMPFEST 13》就能找到官方flag和题解  
当然也可以follow[@Lyther](https://github.com/Lyther)，根据当天的star记录及时得到一把梭工具  

# Archaeology
内存取证题目，使用[ volatility ](https://github.com/volatilityfoundation/volatility)进行分析：  
P.S volatility是一款极其强大的内存分析工具，可以分析内存类型、用户账户、进程状态、导出进程、导出文件、导出NTLM、查看cmd记录、查看注册表信息、查看浏览器记录、内存屏幕截图等，而且支持插件  

首先分析内存类型
>volatility -f memory imageinfo  
```
INFO    : volatility.debug    : Determining profile based on KDBG search...  
          Suggested Profile(s) : WinXPSP2x86, WinXPSP3x86 (Instantiated with WinXPSP2x86)  
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)  
                     AS Layer2 : FileAddressSpace (REDACTED\memory)  
                      PAE type : PAE   
                           DTB : 0xa8f000L  
                          KDBG : 0x80545ce0L  
          Number of Processors : 1  
     Image Type (Service Pack) : 2  
                KPCR for CPU 0 : 0xffdff000L  
             KUSER_SHARED_DATA : 0xffdf0000L  
           Image date and time : 2021-08-06 16:43:57 UTC+0000  
     Image local date and time : 2021-08-07 00:43:57 +0800  
```
根据分析结果，该文件大概率是WinXPSP2x86的内存转储  
接下来看看运行的进程：  
>volatility -f memory --profile=WinXPSP2x86 pslist
```
Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit
---------- -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0x817bd830 System                    4      0     56      240 ------      0
0x815c6ca8 smss.exe                396      4      3       19 ------      0 2021-08-06 16:38:23 UTC+0000
0x8159c2f0 csrss.exe               620    396      8      337      0      0 2021-08-06 16:38:23 UTC+0000
0x815651f8 winlogon.exe            640    396     17      219      0      0 2021-08-06 16:38:23 UTC+0000
0x815a05b0 services.exe            684    640     16      256      0      0 2021-08-06 16:38:23 UTC+0000
0x8153dda0 lsass.exe               696    640     26      341      0      0 2021-08-06 16:38:23 UTC+0000
0x81517b28 vmacthlp.exe            860    684      1       24      0      0 2021-08-06 16:38:23 UTC+0000
0x814fe418 svchost.exe             892    684      7      107      0      0 2021-08-06 16:38:23 UTC+0000
0x814dfc38 svchost.exe             980    684      9      211      0      0 2021-08-06 16:38:23 UTC+0000
0x814cd4e0 svchost.exe            1096    684     43      725      0      0 2021-08-06 16:38:23 UTC+0000
0x814cc8e0 svchost.exe            1108    684      7       81      0      0 2021-08-06 16:38:23 UTC+0000
0x814acda0 explorer.exe           1268   1204     13      309      0      0 2021-08-06 16:38:24 UTC+0000
0x8147fc88 vmtoolsd.exe           1416   1268      5      137      0      0 2021-08-06 16:38:25 UTC+0000
0x8147eb70 ctfmon.exe             1424   1268      1       36      0      0 2021-08-06 16:38:25 UTC+0000
0x81497538 IEXPLORE.EXE           1588   1268     36      897      0      0 2021-08-06 16:38:38 UTC+0000
0x81514608 VGAuthService.e        1680    684      2       61      0      0 2021-08-06 16:38:42 UTC+0000
0x81467420 svchost.exe            1788   1652      3      110      0      0 2021-08-06 16:38:43 UTC+0000
0x8155ba90 vmtoolsd.exe           1832    684      8      227      0      0 2021-08-06 16:38:49 UTC+0000
0x8145cbe0 svchost.exe             136    684      8      137      0      0 2021-08-06 16:38:50 UTC+0000
0x814000c8 wmiprvse.exe            312    892     11      219      0      0 2021-08-06 16:38:50 UTC+0000
0x813e6530 cmd.exe                1688   1268      1       32      0      0 2021-08-06 16:39:51 UTC+0000
0x813c4678 conime.exe             1708   1688      1       26      0      0 2021-08-06 16:39:51 UTC+0000
0x8151ada0 DumpIt.exe             1252   1268      1       24      0      0 2021-08-06 16:43:56 UTC+0000
```
比较特殊的进程是**IEXPLORE.EXE**浏览器进程和**cmd.exe**进程，从这里下手。  
查看cmd命令记录：
>volatility -f memory --profile=WinXPSP2x86 cmdscan
```
Volatility Foundation Volatility Framework 2.6
**************************************************
CommandProcess: csrss.exe Pid: 620
CommandHistory: 0x3833938 Application: cmd.exe Flags: Allocated, Reset
CommandCount: 16 LastAdded: 15 LastDisplayed: 15
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x404
Cmd #0 @ 0x3832110: It's useless to find so many things
Cmd #1 @ 0x3832ed0: ........................
Cmd #2 @ 0x52c778: what can i do about it
Cmd #3 @ 0x3833360: Heard that there is a one-click cleaning that is very useful
Cmd #4 @ 0x52b3c8: try it
Cmd #5 @ 0x52b7e8: "C:\Documents and Settings\Administrator\??\Oneclickcleanup.exe"
Cmd #6 @ 0x5224a0: what???
Cmd #7 @ 0x52d5c0: what happened??
Cmd #8 @ 0x52d410: who is 1cepeak?
Cmd #9 @ 0x3832de0: what's the meaning of hack?
Cmd #10 @ 0x3830e50: oh,no
Cmd #11 @ 0x52af40: holy shit
Cmd #12 @ 0x3830cf8: aaaaaa
Cmd #13 @ 0x522d28: Nonononononononononononono!!!!!!!!!!!!!!!!
Cmd #14 @ 0x522d88: "C:\Documents and Settings\Administrator\??\Oneclickcleanup.exe"
Cmd #15 @ 0x5224b8: fuc
**************************************************
```
看起来我们的受害者是被**Oneclickcleanup.exe**坑了，找找这个文件的位置：  
（如果你的volatility.exe崩掉了，请在劣质终端使用chcp 65001指定编码再执行）
>volatility -f memory --profile=WinXPSP2x86 filescan | grep "Oneclickcleanup"
```
0x00000000017bcbc0      1      0 R--rw- \Device\HarddiskVolume1\Documents and Settings\Administrator\桌面\Oneclickcleanup.exe
```
根据ID导出：
>volatility -f memory --profile=WinXPSP2x86 dumpfiles -Q 0x00000000017bcbc0 -D ./

导出的dat文件在HEX下看到MZ头，确认是exe程序，放到ida里看下，直接就得到了加密过程：
```cpp
int __cdecl main(int argc, const char **argv, const char **envp){
  FILE *v4; // [esp+10h] [ebp-14h]
  int k; // [esp+14h] [ebp-10h]
  signed int j; // [esp+18h] [ebp-Ch]
  int i; // [esp+1Ch] [ebp-8h]

  __main();
  for ( i = 0; i <= 44; ++i )
    _data_start__[i] ^= key[i % 10];
  for ( j = 0; j < (int)size; ++j )
    data[j] ^= key[j % 10];
  for ( k = 0; k <= 9; ++k )
    puts("Hacked by 1cePack!!!!!!!");
  v4 = fopen(_data_start__, "wb+");
  fwrite(data, size, 1u, v4);
  return 0;
}
```
其中key为this_a_key
```
.data:004B8030 ; char key[11]
.data:004B8030 _key            db 'this_a_key',0       ; DATA XREF: _main+4E↑r
```
写脚本导出用key解密之后的文件：
```python
import struct

_data_start__ = [0x37, 0x52, 0x35, 0x37, 0x30, 0x02, 0x2a, 0x06, 0x00, 0x17, 0x00, 0x1b, 0x49, 0x12, 0x31, 0x05,
                 0x7f, 0x38, 0x00, 0x0d, 0x00, 0x01, 0x07, 0x14, 0x2c, 0x3d, 0x1e, 0x07, 0x09, 0x59, 0x21, 0x1b,
                 0x0c, 0x01, 0x2c, 0x3d, 0x0b, 0x0e, 0x08, 0x09, 0x18, 0x09, 0x1d, 0x16, 0x2c]
key = b"this_a_key"
file_name = ""
for i in range(len(_data_start__)):
    file_name += chr(_data_start__[i] ^ key[i % 10])

print(file_name)
f = open("1.doc", "wb")
dat = b""
data = open("file.None.0x81482a50.dat", "rb").read()[0xb7240:0xb7240 + 11776]
for i in range(11776):
    dat += struct.pack("B", data[i] ^ key[i % 10])

f.write(dat)
f.close()
```
其中的filename是C:\Documents and Settings\All Users\Templates，可知被写入的解密文件是XP系统下的宏病毒，但是分析宏病毒比较困难  
这里已经可以根据提示（遇事不决XOR看看）交给CyberChief来XOR Brute Force整个文件一下  
在2d做key时得到flag