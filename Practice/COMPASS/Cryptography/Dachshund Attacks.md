# Dachshund Attacks 10
>What if d is too small? Connect with nc mercury.picoctf.net 58978.

# Explore
提示选用的d很小，参考[wiki](https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_d_attack/)可以考虑[Wiener's attack](https://en.wikipedia.org/wiki/Wiener%27s_attack)

# Decrypt
```python
import owiener

c = your_c
e = your_e
n = your_n

d = owiener.attack(e, n)
print(bytes.fromhex(hex(pow(c,d,n))[2:]))
```
得到falg