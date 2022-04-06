# not crypto 15
>there's crypto in here but the challenge is not crypto... 🤔

# Slove
程序放到ida里看一下，发现正确的输入会输出**Yep, that's it!**  
用angr求解什么样的输入会输出Yep, that's it!
```python
import angr

sim = angr.Project("not-crypto").factory.simgr()
sim.explore(find=lambda s: b"Yep, that's it!" in s.posix.dumps(1))
print(sim.found[0].posix.dumps(0))
```
得到flag