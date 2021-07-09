# collision 5
>Daddy told me about cool MD5 hash collision today. I wanna do something like that too!  
ssh col@pwnable.kr -p2222 (pw:guest)  
The flag IS NOT in the regular format

# Explore
看起来并不像一个pwn题目
```cpp
unsigned long check_password(const char* p) {
    int* ip = (int*)p;
    int res = 0;
    for (int i = 0; i < 5; i++) {
        res += ip[i];
    }
    return res; //correct if  res == 0x21DD09EC
}
```
输入构造有点头疼，而且是int转ulong。不过既然是表达式计算的题，为什么不交给angr求解呢（逃
```python
import angr
import claripy

proj = angr.Project("./col")
arg = claripy.BVS("argv1", 21 * 8)
initial_state = proj.factory.entry_state(args=["./col", arg])
simgr = proj.factory.simulation_manager(initial_state)
simgr.explore(find=0x8048575)   # address of system("/bin/cat flag");
solution = simgr.found[0].solver.eval(arg, cast_to=bytes)
print(solution)
```
angr找到了一个合法的输入**b'\xfc\xb7\xa4\x84\x10*\xbc\xd7\xeb\xce\x1e\x06aDU\xdb\x94\x14\x08\xe4\x00'**

# Pwn！
在终端上执行
>from pwn import *  
p=process(argv=["./col", b'\xfc\xb7\xa4\x84\x10*\xbc\xd7\xeb\xce\x1e\x06aDU\xdb\x94\x14\x08\xe4\x00'])  
p.interactive()  

得到flag  