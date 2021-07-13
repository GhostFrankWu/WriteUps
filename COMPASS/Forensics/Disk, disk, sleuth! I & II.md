# Disk, disk, sleuth! 10
>Use srch_strings from the sleuthkit and some terminal-fu to find a flag in this disk image: dds1-alpine.flag.img.gz

直接用文本编辑器打开搜索picoCTF得到flag

# Disk, disk, sleuth! II 15
>All we know is the file with the flag is named down-at-the-bottom.txt... Disk image: dds2-alpine.flag.img.gz

Windows用户可以使用FTK Imager取证，导入镜像之后在root目录下找到down-at-the-bottom.txt，得到flag
