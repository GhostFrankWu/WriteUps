# Cookies 5
>Who doesn't love cookies? Try to figure out the best one.
http://mercury.picoctf.net:54219/

## Explore
试了试并不是注入，填浏览器的cookie也不正确，填入**snickerdoodle**时出现
> That is a cookie! Not very special though...  

看起来对了，但没完全对，发现此时cookie的name由-1变成了0，试试把name改成别的值post上去，发现返回的文本会有变化  

## Exploitation
name的值从0到30爆破，最后在name=18时得到flag