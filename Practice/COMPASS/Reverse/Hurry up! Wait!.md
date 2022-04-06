# Hurry up! Wait! 10
>svchost.exe

# Slove
拖到ida里，主函数里调用的第二个函数看起来是写了计划任务，过很久很久执行
```cpp
__int64 sub_298A()
{
  ada__calendar__delays__delay_for(1000000000000000LL);
  sub_2616();
  sub_24AA();
  sub_2372();
  sub_25E2();
  sub_2852();
  sub_2886();
  sub_28BA();
  sub_2922();
  sub_23A6();
  sub_2136();
  sub_2206();
  sub_230A();
  sub_2206();
  sub_257A();
  sub_28EE();
  sub_240E();
  sub_26E6();
  sub_2782();
  sub_28EE();
  sub_2102();
  sub_23DA();
  sub_226E();
  sub_21D2();
  sub_2372();
  sub_23A6();
  sub_21D2();
  return sub_2956();
}
```
每个子函数写了一个字符，点进去，拼起来得到flag

# Try
也许在合适版本的计算机可以直接运行，然后去改计划任务的时间？