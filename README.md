# s2-061-rce
s2-061批量扫描兼命令执行exp

## 采用漏洞环境
https://github.com/vulhub/vulhub/tree/master/struts2/s2-061

##使用方法

``` python3 exp.py --help 查看帮助 ```
``` python3 exp.py --url http://ip:port/ --cmd command   #对单一目标执行命令 ``` 
``` python3 exp.py --file target.txt    批量扫描目标，target.txt为待扫描的url，一行一个 ```
