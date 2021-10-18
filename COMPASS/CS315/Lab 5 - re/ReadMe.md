# 1 De-Android
通过apktool将apk转为jar（dex2jar，jadx，jeb亦可）  
通过idea反编译jar（jd-gui，recaf亦可）
```java
public void submitPassword(View paramView) {
    EditText editText = (EditText)findViewById(2131165239);
    if (DigestUtils.md5Hex(editText.getText().toString()).equalsIgnoreCase("b74dec4f39d35b6a2e6c48e637c8aedb")) {
      TextView textView = (TextView)findViewById(2131165322);
      StringBuilder stringBuilder = new StringBuilder();
      stringBuilder.append("Success! CTFlearn{");
      stringBuilder.append(editText.getText().toString());
      stringBuilder.append("_is_not_secure!}");
      textView.setText(stringBuilder.toString());
    } 
  }
```
根据提示，md5的值应该在某些大型数据库里有记录，找在线平台尝试解密  
得到md5("Spring2019")=b74dec4f39d35b6a2e6c48e637c8aedb  
根据格式补全flag

# 2 Touhou Players Win Twice
准备祭出各种大杀器分析数据文件，结果题目一血被拿了，群友A题速度恐怖如斯。  
推测flag位置应该比较显眼，于是转换思路：  
>strings taisei.exe > 1.txt & cat 1.txt | grep flag{

找到了flag的开头部分，果然在没加壳的exe里放着  
flag全部在出现 **flag{** 往后的几百行附近，手动拼接就可以了，注意连续的64位（32个字符）中，前16字符和后16字符的先后顺序是反着的。

拼接得到flag

# javaisez3

被这题支配过，而且原题几乎是jar逆向的天花板，所以就厚颜无耻地照着[ 原题出题人的wp ](https://itzsomebody.xyz/2021/07/11/javaisez3-writeup.html)做了  
  
本题在原题基础上删去了java对zip类"/"结尾文件的特殊处理和忽略CRC的特性的考察，其它考点不变。  

P.S. 原题出题人编程只是业余爱好，主业是数学...

