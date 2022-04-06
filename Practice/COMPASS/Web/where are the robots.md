# where are the robots 10
>Can you find the robots? https://jupiter.challenges.picoctf.org/problem/60915/ (link)[https://jupiter.challenges.picoctf.org/problem/60915/] or http://jupiter.challenges.picoctf.org:60915

# Exploit
访问https://jupiter.challenges.picoctf.org/problem/60915/robots.txt ,找到
>User-agent: *  
Disallow: /8028f.html

访问https://jupiter.challenges.picoctf.org/problem/60915/8028f.html  
得到flag