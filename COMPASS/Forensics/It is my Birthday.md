# It is my Birthday 10
>I sent out 2 invitations to all of my friends for my birthday! I'll know if they get stolen because the two invites look similar, and they even have the same md5 hash, but they are slightly different! You wouldn't believe how long it took me to find a collision. Anyway, see if you're invited by submitting 2 PDFs to my website. http://mercury.picoctf.net:63578/

# Explore
随便交两个pdf上去，会提示
>MD5 hashes do not match!

PHP如果md5计算得到0e开头的结果，会有
>[魔法 Hash ](https://ctf-wiki.org/web/php/php/)   
"0e132456789"=="0e7124511451155" //true  
"0e123456abc"=="0e1dddada" //false  
"0e1abc"=="0"  //true  
在进行比较运算时，如果遇到了 0e\d+ 这种字符串，就会将这种字符串解析为科学计数法。所以上面例子中 2 个数的值都是 0 因而就相等了。如果不满足 0e\d+ 这种模式就不会相等。

找几个[md5是0e开头的字符串](https://www.jianshu.com/p/5bef1f98ca22)
>QNKCDZO  
0e830400451993494058024219903391  
s878926199a  
0e545993274517709034328855841020   

放到txt文件中，后缀改为.pdf，上传得到flag