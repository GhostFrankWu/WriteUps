# scrambled-bytes 20
>I sent my secret flag over the wires, but the bytes got all mixed up!

## Explore
混淆、发包的逻辑
```python
def main(args):
  with open(args.input, 'rb') as f:
    payload = bytearray(f.read())
  random.seed(int(time()))
  random.shuffle(payload)
  with IncrementalBar('Sending', max=len(payload)) as bar:
    for b in payload:
      send(
        IP(dst=str(args.destination)) /
        UDP(sport=random.randrange(65536), dport=args.port) /
        Raw(load=bytes([b^random.randrange(256)])),
      verbose=False)
      bar.next()
```
用时间做种子看起来很安全，可是 **int(time())** 对时间以秒为单位取了整，而数据包又自带时间戳。  
第一个byte是1614044650发出的，所以时间就在1614044650附近。
用WireShark导出所有udp包到res.json文件，计数总共发了1992个byte。
## Reverse
- 只要随机数种子一样，之后得到了随机数序列就是一样的
- 只要shuffle数据的长度一样，之后得到的随机数也是一样的
```python
import random

random.seed(24)
random.shuffle(bytearray(b"1195141"))
a1 = random.randrange(65536)
a2 = random.randrange(256)

random.seed(24)
random.shuffle(bytearray(b"1919810"))
b1 = random.randrange(65536)
b2 = random.randrange(256)

assert(a1 == b1)
assert(a2 == b2)
```
## Slove
写脚本爆出种子对应的shuffle顺序，之后复原文件  
第一次跑完发现是png，所以脚本就直接写成png了  
```python
import random
import json

order = []
for i in range(0, 1992):
    random.seed(1614044650)
    arr = bytearray(b'a' * i + b'0' + b'a' * (1991 - i))
    random.shuffle(arr)
    order.append(arr.index(b"0"))
assert (len(set(order)) == 1992)
random.seed(1614044650)
random.shuffle(bytearray(b'a' * 1992))
s = json.load(open("res.json", "r", encoding="utf-8"))
t = []
for i in s:
    if i['_source']['layers']["frame"]['frame.len'] == '43':
        assert (random.randrange(65536) == int(i['_source']['layers']["udp"]['udp.srcport']))
        c = int(i['_source']['layers']["udp"]['udp.payload'], 16)
        assert (0 <= c < 256)
        b = c ^ random.randrange(256)
        t.append(b)

f = open("res.png", "wb")
for i in order:
    f.write(bytes.fromhex(hex(t[i])[2:].rjust(2,'0')))
f.close()
```
打开res.png，得到flag