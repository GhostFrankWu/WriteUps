# advanced-potion-making 15
>Ron just found his own copy of advanced potion making, but its been corrupted by some kind of spell. Help him recover it!

## Slove

参照 [Ctf-Wiki](https://ctf-wiki.org/misc/picture/png/) 的文件头
>80 59 4e 47 0d 0a 1a 0a  00 00 00 0d 49 48 44 52

覆盖现有文件头，可以正常打开图片
在红色通道低位(Red-0)可以看到flag，或者直接随机亦或整张图片得到flag
```python
from PIL import Image

def fun(y):
    return y^random.randint(0,256)
Image.eval(Image.open("advanced-potion-making"), fun).show()
```
