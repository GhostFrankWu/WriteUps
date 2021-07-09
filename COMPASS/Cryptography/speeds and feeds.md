# speeds and feeds 5
>There is something on my shop network running at nc mercury.picoctf.net 20301, but I can't tell what it is. Can you?

# Explore
nc过去，得到一长串奇怪的东西
>G17 G21 G40 G90 G64 P0.003 F50

丢谷歌一下，发现是3D打印的g-code，找个 [g-code在线模拟网站](http://nraynaud.github.io/webgcode/) 把代码粘进去  
获得打印出的3D flag