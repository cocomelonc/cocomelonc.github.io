---
title:  "Conti ransomware source code investigation - part 2."
date:   2022-04-11 10:00:00 +0600
header:
  teaser: "/assets/images/49/2022-04-11_12-39.png"
categories:
  - investigation
tags:
  - ransomware
  - windows
  - malware
  - red team
  - evasion
  - conti
---

﷽

Hello, cybersecurity enthusiasts and white hackers!

![conti](/assets/images/49/2022-04-11_12-39.png){:class="img-responsive"}    

This post is the second part of my own Conti ransomware source code investigation.    

[first part](/investigation/2022/03/27/malw-inv-conti-1.html)    

In the last part, I wrote about encryption/hashing methods and bypassing AV-engines. Today I will consider network connections and filesystem and some identified IoCs.    

### network connections

First of all, let's go back a little to the logic of the encryptor:    

![conti](/assets/images/49/2022-04-11_13-01.png){:class="img-responsive"}    

As you can see when the encryption mode is `ALL_ENCRYPT` or `NETWORK_ENCRYPT`, the malware retrieves info about network.    

Let's go to definition of `StartScan`:    

![conti](/assets/images/49/2022-04-11_13-15.png){:class="img-responsive"}    

Let's go to deep into logic of network_connections.    

`GetCurrentIpAddress` is just get info about current IP address:   

![conti](/assets/images/49/2022-04-11_13-21.png){:class="img-responsive"}    

Function `GetSubnets` uses `GetIpNetTable` API which is called to restore the ARP table of the infected system. For earch entry the specified IPv4 addresses are checked against the following masks:    

![conti](/assets/images/49/2022-04-11_13-28.png){:class="img-responsive"}    

If the current ARP matches of this masks (`172.*, 192.168.*, 10.*, 169.*`) the subnet is extracted and added to the subnet's queue:    

![conti](/assets/images/49/2022-04-11_13-36.png){:class="img-responsive"}    

![conti](/assets/images/49/2022-04-11_13-41.png){:class="img-responsive"}    

![conti](/assets/images/49/2022-04-11_13-41_1.png){:class="img-responsive"}    

Function `ScanHosts` tries a connection to IPv4 on the SMB port (445) using the TCP protocol:    

![conti](/assets/images/49/2022-04-11_13-44.png){:class="img-responsive"}    

If connection is successfull, saves the valid IP's via `AddHost`:    

![conti](/assets/images/49/2022-04-11_13-47.png){:class="img-responsive"}    

in a queue:    

![conti](/assets/images/49/2022-04-11_13-49.png){:class="img-responsive"}    

And what about `HostHandler`:    

![conti](/assets/images/49/2022-04-11_13-55.png){:class="img-responsive"}    

and `PortScanHandler`:    

![conti](/assets/images/49/2022-04-11_13-57.png){:class="img-responsive"}    

`HostHandler` waits for some valid IP in the IP's queue and for each IP enum the shares using the `NetShareEnum` API:

![conti](/assets/images/49/2022-04-11_14-01.png){:class="img-responsive"}    

![conti](/assets/images/49/2022-04-11_14-03.png){:class="img-responsive"}    

And `PortScanHandler` **(1)** repeat the scan via `ScanHosts` **(2)** each `30` sec. **(3)**:    

![conti](/assets/images/49/2022-04-11_14-12.png){:class="img-responsive"}    

So, what happens when calls `network_scanner::StartScan`?   

1. Add `172.*, 192.168.*, 10.*, 169.*` subnet addresses to queue.    
2. Create two threads.    
3. First thread via `HostHandler` enum the shares.   
4. Second thread via `PortScanHandler` tries to connect `SMB 445` port, for earh successfully connection, saves valid IPs and scan every `30` sec:    

![conti](/assets/images/49/2022-04-11_14-16.png){:class="img-responsive"}    

Concluding the execution, the `WaitForSingleObject` API is invoked on each thread to wait for the completion of operations before closing the main process and `CloseHandle` for cleanup:    

![conti](/assets/images/49/2022-04-11_14-27.png){:class="img-responsive"}    

### process killer

The logic of the `prockiller.cpp` is simple. It enum through all processes and if it's not equal to `explorer.exe` then adds it's PID to the queue:    

![conti](/assets/images/49/2022-04-11_14-36.png){:class="img-responsive"}    

### filesystem

In the `filesystem` module there is a function `filesystem::EnumirateDrives` which, as the name implies, scan drives:    

![conti](/assets/images/49/2022-04-11_14-50.png){:class="img-responsive"}    

As you can see it uses `GetLogicalDriveStringsW` API.    

The logic of this function is used in the final enumeration during encryption. The malware uses a whitelist for both directories and files to avoid the encryption of unnecessary data. The following directories names and file names are avoided during the enumeration process:

![conti](/assets/images/49/2022-04-11_14-59.png){:class="img-responsive"}    

![conti](/assets/images/49/2022-04-11_15-47.png){:class="img-responsive"}    

### yara rules

Let's go to upload `locker.exe` to VirusTotal:    

![conti](/assets/images/49/2022-04-11_16-27.png){:class="img-responsive"}    

[https://www.virustotal.com/gui/file/e1b147aa2efa6849743f570a3aca8390faf4b90aed490a5682816dd9ef10e473/detection](https://www.virustotal.com/gui/file/e1b147aa2efa6849743f570a3aca8390faf4b90aed490a5682816dd9ef10e473/detection)    

**57 of 69 AV engines detect this sample as malware**

Yara rule for Conti:    

```yaml
rule Conti
{
    meta:
        author = "kevoreilly"
        description = "Conti Ransomware"
        cape_type = "Conti Payload"
    strings:
        $crypto1 = {8A 07 8D 7F 01 0F B6 C0 B9 ?? 00 00 00 2B C8 6B C1 ?? 99 F7 FE 8D [2] 99 F7 FE 88 ?? FF 83 EB 01 75 DD}
        $website1 = "https://contirecovery.info" ascii wide
        $website2 = "https://contirecovery.best" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of them
}
```

I hope this post spreads awareness to the blue teamers of this interesting malware techniques, and adds a weapon to the red teamers arsenal.      

[first part](/investigation/2022/03/27/malw-inv-conti-1.html)    
[WSAStartup](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsastartup)    
[WSAAdressToStringA](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaaddresstostringa)    
[CreateToolhelp32Snapshot](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)    
[CloseHandle](https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle)    
[StrStrIW](https://docs.microsoft.com/en-us/windows/win32/api/shlwapi/nf-shlwapi-strstriw)    
[CreateThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread)    
[WaitForSingleObject](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)    
[NetShareEnum](https://docs.microsoft.com/en-us/windows/win32/api/lmshare/nf-lmshare-netshareenum)    
[GetLogicalDriveStringsW](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getlogicaldrivestringsw)    

> This is a practical case for educational purposes only.      

Thanks for your time happy hacking and good bye!   
*PS. All drawings and screenshots are mine*
