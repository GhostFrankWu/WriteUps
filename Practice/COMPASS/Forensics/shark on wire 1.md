# shark on wire 1 15
>We found this packet capture. Recover the flag.

# Explore
wireshark打开pcap，导出到json查找文本"picoCTF"没有找到，查找单个字符载荷
>"data.data": "7b",

找到两个特征流**udp.stream eq 6**和**udp.stream eq 7**  
在wireshark里筛选**udp.stream eq 7**得到picoCTF{N0t_a_flag}，是假flag  
筛选**udp.stream eq 6**得到真flag。