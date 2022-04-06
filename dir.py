import os
from urllib.parse import quote

res = '''# WriteUps
`记录比赛和成长过程，不一定是精选，会有很菜的内容`

年 | 比赛名称 | 主办方 | 参与形式 | 排名
--- | --- | --- | --- | ---\n'''


def analysis(path, level):
    global res
    dirs = os.listdir(path)
    dirs.sort()
    for i in dirs:
        if ".git" in i or "Practice" in i:
            continue
        sub_path = path + '/' + i
        if os.path.isdir(sub_path):
            sub_level = level + 1
            analysis(sub_path, sub_level)
        elif "readme" in i.lower() and "20" in sub_path:
            _, year, info, _ = sub_path.split("/")
            name, host, form, rank = str(info).split("#")

            res += f"{year} | [{name}]({quote(sub_path)}) | {host} | {form} | {rank}\n"


if __name__ == '__main__':
    analysis(path=".", level=1)
    with open("ReadMe.md", "w", encoding="utf8") as f:
        f.write(res)
        f.close()