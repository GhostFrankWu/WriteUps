# Scavenger Hunt 5
>There is some interesting information hidden around this site http://mercury.picoctf.net:5080/. Can you find it?

# Solve
查看源代码得到第一部分flag
>\<!-- Here's the first part of the flag: -->

查看css得到
>/* CSS makes the page look nice, and yes, it also has part of the flag. Here's part 2:  */

查看js得到
>/* How can I keep Google from indexing my website? */

去robots.txt得到第三部分flag

>\# I think this is an apache server... can you Access the next flag?

访问.htaccess (apache分布式配置文件)得到第四部分flag
>\# I love making websites on my Mac, I can Store a lot of information there.

访问.DS_Store 得到第五部分flag
>Congrats! You completed the scavenger hunt. Part 5: 

