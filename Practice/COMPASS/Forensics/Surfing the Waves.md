# Surfing the Waves 25
>While you're going through the FBI's servers, you stumble across their incredible taste in music. One main.wav you found is particularly interesting, see if you can find the flag!

## Explore
binwalk，频谱图，SilentEye低位隐写都没有结果  
附加信息和strings也没有扫出stegHide的密码  

读wav文件头得到文件是单声道16比特，写脚本读wav的每个采样
```python
data = open("main.wav", "rb").read()[44:]
hi = []
lo = []
for i in range(0, len(data), 2):
    lo.append(data[i])
    hi.append(data[i + 1])
print(len(set(hi)), hi)
print(len(set(lo)), lo)
```
发现高位的数据都很小且总共只有16种数据
> \>\>\>print(set(hi))  
> {33, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31}
## Slove

假设16分别代表hex的0-f，尝试写脚本输出
```python
data = open("main.wav", "rb").read()[44:]
b = ""
for i in range(0, len(data), 2):
    b += str(hex(int(data[i + 1] / 2) - 1)[2:])
print(bytes.fromhex(b))
```
得到音频的生成脚本和flag