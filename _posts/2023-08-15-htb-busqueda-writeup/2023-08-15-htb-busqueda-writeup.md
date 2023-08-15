---
layout: post
title: HTB Busqueda Writeup
date: 2023-08-15 19:06 +0600
author: animesh
toc: true
tags: ["htb", "hackthebox", "Searchor_exploit", "git_config"]
categories: ["Hackthebox"]
render_with_liquid: false
comments: true
image:
  path: /posts/htb-busqueda-writeup/Busqueda%2081bfdb43145741e49cfc773652f7ec98/Busqueda.png
  alt: HTB Busqueda
---

## Overview

This was a fairly easy box. Firstly a public exploit leads to user flag and from there it was easy to get root via sudo

![Busqueda.png](Busqueda%2081bfdb43145741e49cfc773652f7ec98/Busqueda.png)

**Name -** Busqueda

**Difficulty -** Easy

**OS -** Linux

**Points -** 20

## Information Gathering

### Port Scan

Basic Scan

```bash
╰─ nmap 10.10.11.208
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-11 10:04 EDT
Nmap scan report for 10.10.11.208
Host is up (0.15s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 12.03 seconds
```

Version Scan

```bash
╰─ nmap 10.10.11.208 -sC -sV -p22,80
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-11 10:06 EDT
Nmap scan report for 10.10.11.208
Host is up (0.054s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
|_  256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://searcher.htb/
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.25 seconds
```

### **HTTP Enumeration**

Visiting the website gives us the following

![Untitled](Busqueda%2081bfdb43145741e49cfc773652f7ec98/Untitled.png)

The website is running Searchor 2.4.0 which has Arbitrary Command Injection Vulnerability. I found this [github](https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection) repo for exploiting this.

After running the exploit, I was able to get the user

![Untitled](Busqueda%2081bfdb43145741e49cfc773652f7ec98/Untitled%201.png)

## Getting User.txt

After that, I quickly grabbed the user flag

![Untitled](Busqueda%2081bfdb43145741e49cfc773652f7ec98/Untitled%202.png)

User Flag - 311ebe6e0002861b0be60a66faaa2b75

## Getting root.txt

Found domain and credential (**cody:jh1usoih2bkjaspwe92**) for gitea server.

![Untitled](Busqueda%2081bfdb43145741e49cfc773652f7ec98/Untitled%203.png)

With the credential, I was able to log in to the gitea server.

![Untitled](Busqueda%2081bfdb43145741e49cfc773652f7ec98/Untitled%204.png)

But, There is not much information in the gitea server. I used password for sudo and it was successful.

![Untitled](Busqueda%2081bfdb43145741e49cfc773652f7ec98/Untitled%205.png)

I ran that with

```bash
sudo -u root /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
```

![Untitled](Busqueda%2081bfdb43145741e49cfc773652f7ec98/Untitled%206.png)

But in different directory it does not work

![Untitled](Busqueda%2081bfdb43145741e49cfc773652f7ec98/Untitled%207.png)

And /opt/scripts folder contains a file named full-checkup.sh

![Untitled](Busqueda%2081bfdb43145741e49cfc773652f7ec98/Untitled%208.png)

So, It is executing full-checkup.sh script from the current working directory. I made one script to copy /bin/bash to current directory and then give it setuid permission and that gave me the root shell

![Untitled](Busqueda%2081bfdb43145741e49cfc773652f7ec98/Untitled%209.png)

Got the root flag after that

![Untitled](Busqueda%2081bfdb43145741e49cfc773652f7ec98/Untitled%2010.png)

Root Flag - 03b5ceca8c817263fa24cf2956835588

## Flags

**user.txt -** 311ebe6e0002861b0be60a66faaa2b75

**root.txt -** 03b5ceca8c817263fa24cf2956835588
