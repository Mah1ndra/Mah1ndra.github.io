---
layout: single
title: Zetta - Hack The Box
excerpt: "Zetta is another amazing box by [jkr](https://twitter.com/ateamjkr). The first part was kinda tricky because you had to pay attention to the details on the webpage and spot the references to IPv6 that lead you to the EPTR command to disclose the IPv6 address of the server. Then there's some light bruteforcing of rsync's credentials with a custom bruteforce script and finally a really cool SQL injection in a syslog PostgreSQL module."
date: 2020-03-07
classes: wide
header:
  teaser: /assets/images/htb-writeup-zetta/zetta_logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:
  - ipv6
  - rsync
  - sqli
  - postgresql
---
