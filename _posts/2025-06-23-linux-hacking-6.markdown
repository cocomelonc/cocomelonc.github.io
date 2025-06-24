---
title:  "Linux hacking part 6: Linux kernel module with params. Simple C example"
date:   2025-06-23 02:00:00 +0200
header:
  teaser: "/assets/images/160/2025-06-24_09-55.png"
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

![malware](/assets/images/160/2025-06-24_09-55.png){:class="img-responsive"}    

In the [previous post](/linux/2024/06/20/linux-kernel-hacking-1.html), we discussed the basics of kernel hacking and the process of writing and loading a simple kernel module. Now, let's take things further by adding functionality to our module using parameters passed from the command line.    

One of the coolest features of kernel modules is the ability to interact with them dynamically. Instead of hardcoding values, we can expose parameters that can be modified at runtime, giving us more flexibility and control over the module's behavior.    

In this post, I'm going to show you how to pass string and integer parameters to your kernel module, and based on those parameters, you can customize the behavior of your module.     

### practical example

In Linux kernel modules, you can expose parameters using the `module_param` macro. This macro allows us to declare a parameter that will be passed to the module when it is loaded.     

First of all, look at the previous module code:    

```c
/*
 * hack.c
 * introduction to linux kernel hacking
 * author @cocomelonc
 * https://cocomelonc.github.io/linux/2025/06/23/kernel-hacking-6.html
*/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("cocomelonc");
MODULE_DESCRIPTION("kernel-test-01");
MODULE_VERSION("0.001");

static int __init hack_init(void) {
  printk(KERN_INFO "Meow-meow!\n");
  return 0;
}

static void __exit hack_exit(void) {
  printk(KERN_INFO "Meow-bow!\n");
}

module_init(hack_init);
module_exit(hack_exit);
```

Recheck again, run the following command to compile the module:    

```bash
make
```

![malware](/assets/images/160/2025-06-24_09-49_1.png){:class="img-responsive"}    

![malware](/assets/images/160/2025-06-24_09-49.png){:class="img-responsive"}    

and run:    

```bash
sudo insmod hack.ko
sudo rmmod hack.ko
```

![malware](/assets/images/160/2025-06-24_09-50.png){:class="img-responsive"}    

As you can, as in the previous post, everything is worked perfectly! (the only difference is ubuntu version: `20.04` vs `18.04`)     

![malware](/assets/images/160/2025-06-24_10-07.png){:class="img-responsive"}    

Ok, let's go to add some arguments to this module.      

Let's break down the code and see how we can implement it. Let's say we define a string parameter called `pet` with a default value of `"cat"`:     

```cpp
static char *pet = "cat"; // default value is "cat"
module_param(pet, charp, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(pet, "Pet name: can be cat, mice, bird, dog, or sheep");
```

`module_param` macro declares `pet` as a parameter that can be passed to the module when it's loaded:    

```cpp
module_param(pet, charp, S_IRUSR | S_IWUSR)
```

Here `charp` specifies the type of the parameter (a string), `S_IRUSR | S_IWUSR` means the parameter is readable and writable by the user (the module's owner).     

Then, just update kernel module initialization function (`hack_init`) logic:     

```cpp
static int __init hack_init(void) {
  if (strcmp(pet, "cat") == 0) {
    printk(KERN_INFO "Meow-meow!\n");
  } else if (strcmp(pet, "mice") == 0) {
    printk(KERN_INFO "Squeak-squeak!\n");
  } else if (strcmp(pet, "bird") == 0) {
    printk(KERN_INFO "Twit-twit!\n");
  } else if (strcmp(pet, "dog") == 0) {
    printk(KERN_INFO "Woof-woof!\n");
  } else if (strcmp(pet, "sheep") == 0) {
    printk(KERN_INFO "Baa-baa!\n");
  } else {
    printk(KERN_INFO "unknown pet: %s\n", pet);
  }
  return 0;
}
```

The logic is pretty simple: based on the value of `pet`, a different message is printed using `printk`.    

When the module is unloaded, it logs the message `meeeeeeeeeeeeeeeooooooow!` using `printk`:      

```cpp
static void __exit hack_exit(void) {
  printk(KERN_INFO "meeeeeeeeeeeeeeeooooooow!\n");
}
```

So, final source code is looks like this (`hack2.c`):     

```cpp
/*
 * hack.c
 * kernel hacking: module params
 * author @cocomelonc
 * https://cocomelonc.github.io/linux/2025/06/23/kernel-hacking-6.html
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("cocomelonc");
MODULE_DESCRIPTION("kernel-test-02");
MODULE_VERSION("0.001");

static char *pet = "cat"; // default value is "cat"
module_param(pet, charp, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(pet, "Pet name: can be cat, mice, bird, dog, or sheep");

static int __init hack_init(void) {
  if (strcmp(pet, "cat") == 0) {
    printk(KERN_INFO "Meow-meow!\n");
  } else if (strcmp(pet, "mice") == 0) {
    printk(KERN_INFO "Squeak-squeak!\n");
  } else if (strcmp(pet, "bird") == 0) {
    printk(KERN_INFO "Twit-twit!\n");
  } else if (strcmp(pet, "dog") == 0) {
    printk(KERN_INFO "Woof-woof!\n");
  } else if (strcmp(pet, "sheep") == 0) {
    printk(KERN_INFO "Baa-baa!\n");
  } else {
    printk(KERN_INFO "unknown pet: %s\n", pet);
  }
  return 0;
}

static void __exit hack_exit(void) {
  printk(KERN_INFO "meeeeeeeeeeeeeeeooooooow!\n");
}

module_init(hack_init);
module_exit(hack_exit);
```

### demo

Let's go to see everything in action. Add one line to our first version of Makefile:     

```bash
obj-m += hack2.o
```

So, updated file is like in the following:    

```bash
obj-m += hack.o
obj-m += hack2.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

Ok, then copy to the linux machine and make. When you load the module, you can pass parameters to it using the `insmod` command:     

```bash
make
sudo insmod hack2.ko pet=sheep
```

![malware](/assets/images/160/2025-06-24_09-52.png){:class="img-responsive"}    

Finally, unload the module:     

```bash
sudo rmmod hack2
```

![malware](/assets/images/160/2025-06-24_09-52_1.png){:class="img-responsive"}    

Recheck with different arguments:    

```bash
sudo insmod hack2.ko pet=cat
sudo rmmod hack2
sudo insmod hack2.ko pet=bird
sudo rmmod hack2
sudo insmod hack2.ko pet=dog
sudo rmmod hack2
```

![malware](/assets/images/160/2025-06-24_09-53.png){:class="img-responsive"}    

![malware](/assets/images/160/2025-06-24_09-57.png){:class="img-responsive"}    

### practical example 2

Let's add new integer argument. The second parameter is `count`, which is an integer specifying how many times to print the message. The default value is `1`.      

In this case declaration of module params looks like this:     

```cpp
static char *pet = "cat"; // default value is "cat"
static int count = 1; // default is 1
module_param(pet, charp, S_IRUSR | S_IWUSR);
module_param(count, int, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(pet, "Pet name: can be cat, mice, bird, dog, or sheep");
MODULE_PARM_DESC(count, "count");
```

and kernel module initialization function (`hack_init`) looks like the following:    

```cpp
static int __init hack_init(void) {
  int i;

  for (i = 0; i < count; i++) {
    // output the pet sound depending on the pet parameter
    if (strcmp(pet, "cat") == 0) {
        printk(KERN_INFO "Meow!\n");
    } else if (strcmp(pet, "mice") == 0) {
        printk(KERN_INFO "Squeak!\n");
    } else if (strcmp(pet, "bird") == 0) {
        printk(KERN_INFO "Twit-twit!\n");
    } else if (strcmp(pet, "dog") == 0) {
        printk(KERN_INFO "Woof!\n");
    } else if (strcmp(pet, "sheep") == 0) {
        printk(KERN_INFO "Baa baa!\n");
    } else {
        printk(KERN_INFO "unknown pet: %s\n", pet);
    }
  }

  return 0;
}
```

The loop prints the pet's sound `count` times (which is also passed by the user when the module is loaded).      

So, the full source code is looks like this (`hack3.c`):     

```cpp
/*
 * hack.c
 * kernel hacking: module params 2
 * author @cocomelonc
 * https://cocomelonc.github.io/linux/2025/06/23/kernel-hacking-6.html
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("cocomelonc");
MODULE_DESCRIPTION("kernel-test-03");
MODULE_VERSION("0.001");

static char *pet = "cat"; // default value is "cat"
static int count = 1; // default is 1
module_param(pet, charp, S_IRUSR | S_IWUSR);
module_param(count, int, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(pet, "Pet name: can be cat, mice, bird, dog, or sheep");
MODULE_PARM_DESC(count, "count");

static int __init hack_init(void) {
  int i;

  for (i = 0; i < count; i++) {
    // output the pet sound depending on the pet parameter
    if (strcmp(pet, "cat") == 0) {
        printk(KERN_INFO "Meow!\n");
    } else if (strcmp(pet, "mice") == 0) {
        printk(KERN_INFO "Squeak!\n");
    } else if (strcmp(pet, "bird") == 0) {
        printk(KERN_INFO "Twit-twit!\n");
    } else if (strcmp(pet, "dog") == 0) {
        printk(KERN_INFO "Woof!\n");
    } else if (strcmp(pet, "sheep") == 0) {
        printk(KERN_INFO "Baa baa!\n");
    } else {
        printk(KERN_INFO "unknown pet: %s\n", pet);
    }
  }

  return 0;
}

static void __exit hack_exit(void) {
  printk(KERN_INFO "meeeeeeeeeeeeeeeooooooow!\n");
}

module_init(hack_init);
module_exit(hack_exit);
```

### demo 2

In this case, just add new param:     

```bash
sudo insmod hack3.ko pet=sheep count=7
sudo rmmod hack3.ko
sudo insmod hack3.ko pet=cat count=3
sudo rmmod hack3.ko
sudo insmod hack3.ko pet=dog count=4
sudo rmmod hack3.ko
```

![malware](/assets/images/160/2025-06-24_10-04.png){:class="img-responsive"}    

![malware](/assets/images/160/2025-06-24_10-06.png){:class="img-responsive"}    

As usual, we use `dmesg` to view the kernel messages, which will include the output from `printk`.      

This kernel module demonstrates how to pass parameters at runtime, including strings and integers, and how to use those parameters to influence the behavior of the module. Using `module_param`, we can create flexible modules that can be customized when they are loaded into the kernel, making them far more powerful than static modules.      

You can also modify the values of the parameters without unloading and reloading the module. Simply update the `sysfs` interface:     

```bash
cat /sys/module/hack/parameters/pet
cat /sys/module/hack/parameters/count
```

![malware](/assets/images/160/2025-06-24_22-24.png){:class="img-responsive"}    

As you explore more complex modules, you'll find that parameters can be used for many things, such as controlling logging levels, setting configuration options, or even tweaking performance parameters without needing to recompile or reload the entire module.    

In the future posts of this series I will show more complex, more malicious behavior in our kernel modules. Stay tuned!     

I hope this post with practical example is useful for malware researchers, linux programmers and everyone who interested on linux kernel programming techniques.    

[Linux malware development 1: intro to kernel hacking. Simple C example](/linux/2024/06/20/linux-kernel-hacking-1.html)      
[Linux malware development 2: find process ID by name. Simple C example](/linux/2024/09/16/linux-hacking-2.html)      
[Linux hacking part 5: building a Linux keylogger. Simple C example](/linux/2025/06/03/linux-hacking-5.html)      
[source code in github](https://github.com/cocomelonc/meow/tree/master/2025-06-23-linux-hacking-6)    

> This is a practical case for educational purposes only.

Thanks for your time happy hacking and good bye!         
*PS. All drawings and screenshots are mine*       
