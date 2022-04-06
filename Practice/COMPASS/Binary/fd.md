# fd 5
>Mommy! what is a file descriptor in Linux?  
try to play the wargame your self but if you are ABSOLUTE beginner, follow this tutorial link: https://youtu.be/971eZhMHQQw
ssh fd@pwnable.kr -p2222 (pw:guest)  
The flag IS NOT in the regular format>

# Explore
```cpp
int fd = atoi( argv[1] ) - 0x1234;
        int len = 0;
        len = read(fd, buf, 32);
        if(!strcmp("LETMEWIN\n", buf)){
                printf("good job :)\n");
                system("/bin/cat flag");
                exit(0);
        }
```
程序会将输入的第二个参数减去4660(0X1234)作为文件描述符读取，如果读到的32个字符前缀是"LETMEWIN\n\0"就可以得到flag
- Unix里一切都是文件
- Unix系统中文件描述符0代表std_in
- Unix系统中文件描述符1代表std_out
- Unix系统中文件描述符2代表std_err

# Pwn！
通过echo传入std_in，同时使argv[1]-0x1234=0
>echo "LETMEWIN" | ./fd 4660

得到flag  