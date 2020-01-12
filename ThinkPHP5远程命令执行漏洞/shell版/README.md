# thinkphpV5-rce

#### 概述

支持单url/批量检测。

单url默认格式为http://example.com/index.php

批量检测请将url放入文件，url格式默认为1.1.1.1

#### 需求

python2.7，requests库

#### 快速开始

`python2 thinkphpv5-rce.py`

![帮助](http://bmob-cdn-22571.b0.upaiyun.com/2019/01/17/1236690640fead4280fe54aeb1042a1e.png)

单url模式

`python2 thinkphpv5-rce.py -u http://example.com/index.php`

![单url](http://bmob-cdn-22571.b0.upaiyun.com/2019/01/17/c753c9284020d9258050600572009992.png)

批量模式

`python2 thinkphpv5-rce.py -f urls.txt`

![批量检测](http://bmob-cdn-22571.b0.upaiyun.com/2019/01/17/abf3ba4e406f3fe980bb79ecd50b623f.png)

#### 问题

默认一句话木马名为xxxxx.php，密码为xxxxx。

一句话木马的密码和名字就在exp中，请自行修改，大致在24、30、34~39行。修改之后请修改函数shell_check()中的elif语句，将其改为你自己的密码。



脚本测试是在linux跑的，如果想在windows环境使用，需修改主函数main()，大致193行

```python
target_url = "http://"+url.split("\r\n")[0] + "/index.php?s="
> 
target_url = "http://"+url.split("\n")[0] + "/index.php?s="
```



脚本最后会将有洞的url打印出来，如果想写入文件，请在main函数最后添加代码将results字典写入文件即可。



博客：https://mntn0x.github.io/2019/01/17/ThinkPHP-V5-rce%E6%A3%80%E6%B5%8B%E8%84%9A%E6%9C%AC/