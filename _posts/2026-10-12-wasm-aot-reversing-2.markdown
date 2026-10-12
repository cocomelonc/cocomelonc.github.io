---
title:  "Reversing embedded WebAssembly: part 2. Recovering function names from a WAMR .aot in pure C."
date:   2026-10-12 04:00:00 +0200
header:
  teaser: "/assets/images/228/2026-10-11_15-34.png"
categories:
  - reverse
tags:
  - reverse
  - webassembly
  - wasm
  - wamr
  - aot
  - iot
  - reveng
---

﷽

Hello, cybersecurity enthusiasts and white hackers!

![aot](/assets/images/228/2026-10-11_15-34.png){:class="img-responsive"}     

In [part 1](/reverse/2026/09/30/wasm-aot-reversing-1.html) we reversed the WAMR `.aot` container from real bytes and wrote `unaot` - a tiny, dependency-free C parser that verifies the `\0aot` magic, walks the section table (handling the 4-byte alignment rule), and decodes `TARGET_INFO` so we know exactly which CPU the embedded `TEXT` blob is compiled for.      

That told us *where* the native code is and *how* to disassemble it. But a disassembly of a few hundred anonymous functions is nearly useless. What a reverse engineer actually wants is *names*: which blob of machine code is `add`, which is `fib`, which is the exported entry point. This part builds exactly that - a *symbolized function table* - by decoding two more sections, `EXPORT` and `FUNCTION`, and joining them. We will also give the tool some color so the output is readable. Still one small C file, still no libraries.    

### the plan

The information we need is split across two sections, and neither one is enough on its own:      

- `FUNCTION` gives us, for every *defined* function, the *offset into `TEXT`* where its native code starts (and its type index). It gives us the geography - but no names.      
- `EXPORT` gives us *names* mapped to function *indices* - but no offsets.     

The two share a key: the function index. So the whole trick of part 2 is:    

![aot](/assets/images/228/2026-10-11_15-44.png){:class="img-responsive"}     

Decode both, join on the index, and we have a symbol table that maps every native function to a name and a precise file offset. Let's take the sections one at a time.    

### the EXPORT section

`EXPORT` is the name source. Its layout (from WAMR's `aot_loader.c`, `load_export_section`) is a count followed by that many export entries:    

```cpp
u32 count
entry[count]:
    u32  index          (4-byte aligned)
    u8   kind           0=func 1=table 2=memory 3=global 4=tag
    str  name
```

The one part that will trip you up is how WAMR stores a string. It is *not* a plain C string and *not* a bare length-prefixed buffer. It is:    

```cpp
u16 length          (2-byte aligned)
u8  bytes[length]    <- the trailing '\0' IS counted in length
```

So a name like `add` is stored with `length = 4`: the three characters `a`, `d`, `d`, plus a trailing NUL that is included in the count. If you print `length` bytes you get a stray NUL at the end; if you assume the length excludes the terminator you read one byte short on the next field and desync. We copy `length` bytes and then drop the last one.     

Here is `decode_export`. Note the two alignment steps - `index` is 4-aligned, the string `length` is 2-aligned - mirroring the loader's alignment-aware reads from part 1:     

```c
/* EXPORT: u32 count, then { u32 index(align4), u8 kind, string name }.
 * string = u16 len(align2) + len bytes (trailing '\0' counted in len). */
static void decode_export(reader_t *r, size_t body, uint32_t size) {
  size_t end = body + size, pos = body;
  uint32_t count = rd_u32_at(r, pos); pos += 4;
  if (r->err) { printf("      <export truncated>\n"); return; }
  printf("      %u export(s):\n", count);
  for (uint32_t i = 0; i < count; i++) {
    pos = align_up(pos, 4);
    uint32_t index = rd_u32_at(r, pos); pos += 4;
    uint8_t  kind  = rd_u8_at(r, pos);  pos += 1;
    pos = align_up(pos, 2);
    uint16_t slen  = rd_u16_at(r, pos); pos += 2;
    if (r->err || pos + slen > end) { printf("        <export %u truncated>\n", i); break; }
    char name[96];
    size_t n = slen < sizeof(name) ? slen : sizeof(name) - 1;
    for (size_t j = 0; j < n; j++) name[j] = (char) rd_u8_at(r, pos + j);
    name[n ? n - 1 : 0] = 0;   /* drop the counted trailing '\0' */
    pos += slen;
    printf("        [%u] %-6s index=%-3u  \"%s\"\n",
           i, export_kind_name(kind), index, name);
    if (kind == 0 && g_expn < MAXF) {   /* remember func names for symbolization */
      g_exp[g_expn].index = index;
      snprintf(g_exp[g_expn].name, sizeof(g_exp[g_expn].name), "%s", name);
      g_expn++;
    }
  }
}
```

Every access still goes through the bounds-checked reader, and we clamp against the section `end` before touching a name - a corrupt `.aot` must never walk us off the buffer. We keep only the `kind == 0` (function) exports in a small table `g_exp[]`; that is our index-to-name map.    

### the FUNCTION section

`FUNCTION` is the geography. Its body is two parallel arrays:

```cpp
text_offsets[func_count]        (u64 on a 64-bit target, else u32)
func_type_indexes[func_count]   (u32 each)
```

`text_offsets[i]` is the byte offset into `TEXT` where defined function `i` begins; the size of function `i` is simply `text_offsets[i+1] - text_offsets[i]` (and the last one runs to the end of `TEXT`).     

There is a genuinely annoying catch, and it is worth dwelling on because it is the hardest part of the whole tool. **`func_count` is not stored in this section.** In WAMR it lives deep inside `INIT_DATA`, behind the memory, table, type, import-global, global and import-function tables - a lot of variable-length structures we have not decoded yet. Rather than parse all of `INIT_DATA` just to learn one integer, we *derive* `func_count` from the section size and then validate the guess.     

If there were no other data, `func_count = size / (word_size + 4)` - one word per `text_offset`, one `u32` per type index. But a `wamrc` built with stack-frame support (the prebuilt one is) emits two extra `u32` arrays per function, so each entry is `word_size + 4 + 8` bytes instead. We do not know up front which layout a given file uses, so we *try both* and keep the one that validates. A layout is accepted only if:     

- the section size divides evenly by the per-entry size, and
- every decoded `text_offset` is within `TEXT`, and the offsets are non-decreasing (functions are laid out in order).    

That second check is what makes the guess safe: a wrong layout produces offsets that are out of range or out of order almost immediately, so it gets rejected.    

```c
/* try to read the FUNCTION section assuming `extra` bytes of per-func trailing
 * arrays (0 = no stack-frame info). returns func_count on success, else 0. */
static uint32_t try_func_layout(reader_t *r, size_t body, uint32_t size, uint32_t extra) {
  uint32_t wsz = g_is64 ? 8 : 4;
  uint32_t entry = wsz + 4 + extra;
  if (entry == 0 || size % entry != 0) return 0;
  uint32_t fc = size / entry;
  if (fc == 0 || fc > MAXF) return 0;
  uint64_t prev = 0;
  for (uint32_t i = 0; i < fc; i++) {
    uint64_t o = g_is64 ? rd_u64_at(r, body + (size_t) i * 8)
                        : rd_u32_at(r, body + (size_t) i * 4);
    if (r->err || o >= g_code_size || (i > 0 && o < prev)) return 0; /* sorted, in-range */
    prev = o;
  }
  return fc;
}

/* FUNCTION: text_offsets[fc] then func_type_indexes[fc] (u32). fc is not in
 * this section (it lives in INIT_DATA), so derive it and validate. */
static void decode_function(reader_t *r, size_t body, uint32_t size) {
  if (g_code_size == 0) { printf("      <no TEXT seen yet>\n"); return; }
  uint32_t wsz = g_is64 ? 8 : 4;
  uint32_t fc = try_func_layout(r, body, size, 0);   /* no stack-frame info  */
  if (!fc) fc = try_func_layout(r, body, size, 8);    /* + 2 u32 frame arrays */
  if (!fc) { printf("      <could not determine func_count>\n"); return; }

  for (uint32_t i = 0; i < fc; i++)
    g_foff[i] = g_is64 ? rd_u64_at(r, body + (size_t) i * 8)
                       : rd_u32_at(r, body + (size_t) i * 4);
  size_t tbase = body + (size_t) fc * wsz;
  for (uint32_t i = 0; i < fc; i++) g_ftype[i] = rd_u32_at(r, tbase + (size_t) i * 4);
  g_fcount = fc;
  printf("      %u function(s) (func index -> TEXT offset)\n", fc);
}
```

For our `add.aot` this correctly recovers `3` functions even though `60 / (8 + 4) = 5` is what a naive reader would print - because the prebuilt `wamrc` uses the stack-frame layout, so the real entry size is `8 + 4 + 8 = 20` and `60 / 20 = 3`.     

### joining them into a symbol table

Now the payoff. `func_export_name()` looks a name up by function index, and `print_symbol_table()` walks the functions in order, computes each one's size from the next offset, and prints the native + file offsets next to the recovered name:    

```c
/* name for defined function index i (assumes import_func_count == 0, which
 * holds for self-contained modules - see the caveat at the end). */
static const char *func_export_name(uint32_t i) {
  for (uint32_t k = 0; k < g_expn; k++) if (g_exp[k].index == i) return g_exp[k].name;
  return NULL;
}

static void print_symbol_table(void) {
  if (g_fcount == 0) return;
  printf("\n== functions (symbolized) ==   (text @ file 0x%x, assuming import_func_count=0)\n",
         g_text_foff);
  for (uint32_t i = 0; i < g_fcount; i++) {
    uint64_t foff = g_foff[i];
    uint64_t fend = (i + 1 < g_fcount) ? g_foff[i + 1] : g_code_size;
    uint64_t fsz  = fend > foff ? fend - foff : 0;
    uint64_t file_off = (uint64_t) g_text_foff + foff;
    const char *nm = func_export_name(i);
    printf("  [%2u] text+0x%-6llx  file@0x%-6llx  size=%-4llu  type=%u  %s\n",
           i, (unsigned long long) foff, (unsigned long long) file_off,
           (unsigned long long) fsz, g_ftype[i], nm ? nm : "");
  }
}
```

The `file@` column is the real byte offset you can seek to in a hex editor or feed to a disassembler; `text+` is the offset relative to the start of the code. That is the bridge from "a native blob at offset `0x150`" to "the function `fib` is 56 bytes at file offset `0x170`".      

### a bit of color

Walls of monochrome offsets are hard to scan, so the real `unaot.c` wraps every field in a tiny color helper. The whole mechanism is one global and one macro - colors are emitted only when enabled, so piping to a file or `grep` stays clean:     

```c
static int g_color = 0;
#define CC(s) (g_color ? (s) : "")
#define RST   CC("\x1b[0m")
#define SEC   CC("\x1b[1;33m")   /* bold yellow  */
#define NUM   CC("\x1b[32m")     /* green        */
#define SYM   CC("\x1b[1;35m")   /* bold magenta */
/* ... */
```

We turn it on automatically when stdout is a terminal, and let the user force it either way. This also respects the `NO_COLOR` convention:

```c
g_color = !no_color && (force_color || (isatty(fileno(stdout)) && !getenv("NO_COLOR")));
```

`--color` forces it on (handy for `less -R`), `--no-color` forces it off, and `NO_COLOR=1` in the environment disables it - the listings in this post use `--no-color` so they paste cleanly.

Full source code of part 2 (`reader.h` is unchanged from part 1):     

```c
/*
 * unaot.c
 * part 2: WAMR .aot -> symbolized function table (EXPORT + FUNCTION) + color.
 * author: cocomelonc
 * https://cocomelonc.github.io/reverse/2026/10/14/wasm-aot-reversing-2.html
 */
#define _POSIX_C_SOURCE 200809L  /* isatty / fileno under -std=c11 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "reader.h"

#define AOT_MAGIC 0x746f6100u    /* "\0aot" */

enum {
  AOT_SEC_TARGET_INFO = 0, AOT_SEC_INIT_DATA = 1, AOT_SEC_TEXT = 2,
  AOT_SEC_FUNCTION = 3, AOT_SEC_EXPORT = 4, AOT_SEC_RELOCATION = 5,
  AOT_SEC_SIGNATURE = 6, AOT_SEC_CUSTOM = 100,
};

/* ------------------------------- color ---------------------------------- */
static int g_color = 0;
#define CC(s) (g_color ? (s) : "")
#define RST   CC("\x1b[0m")
#define BOLD  CC("\x1b[1m")
#define DIM   CC("\x1b[2m")
#define TITLE CC("\x1b[1;36m")   /* bold cyan    */
#define SEC   CC("\x1b[1;33m")   /* bold yellow  */
#define NUM   CC("\x1b[32m")     /* green        */
#define SYM   CC("\x1b[1;35m")   /* bold magenta */
#define ARCH  CC("\x1b[1;34m")   /* bold blue    */
#define OKC   CC("\x1b[32m")
#define BADC  CC("\x1b[1;31m")

/* ---------------------------- collected state --------------------------- */
#define MAXF 8192
static int      g_is64 = 1;       /* target word size, from TARGET_INFO */
static uint16_t g_machine = 0;    /* ELF e_machine, from TARGET_INFO    */
static uint32_t g_text_foff = 0;  /* file offset of TEXT body           */
static uint32_t g_code_size = 0;  /* TEXT size                          */
static uint64_t g_foff[MAXF];     /* per-func TEXT offset               */
static uint32_t g_ftype[MAXF];    /* per-func type index                */
static uint32_t g_fcount = 0;
struct expfn { uint32_t index; char name[96]; };
static struct expfn g_exp[MAXF];  /* exported functions (kind=func)     */
static uint32_t g_expn = 0;

static const char *sec_name(uint32_t t) {
  switch (t) {
    case AOT_SEC_TARGET_INFO: return "TARGET_INFO";
    case AOT_SEC_INIT_DATA:   return "INIT_DATA";
    case AOT_SEC_TEXT:        return "TEXT (native code)";
    case AOT_SEC_FUNCTION:    return "FUNCTION";
    case AOT_SEC_EXPORT:      return "EXPORT";
    case AOT_SEC_RELOCATION:  return "RELOCATION";
    case AOT_SEC_SIGNATURE:   return "SIGNATURE";
    case AOT_SEC_CUSTOM:      return "CUSTOM";
    default:                  return "<unknown>";
  }
}
static const char *machine_name(uint16_t m) {
  switch (m) {
    case 0x03: return "x86 (i386)"; case 0x3e: return "x86_64";
    case 0x28: return "ARM (32)";   case 0xb7: return "AArch64";
    case 0xf3: return "RISC-V";     case 0x08: return "MIPS";
    case 0xdc: return "Xtensa (ESP32)"; default: return "<other>";
  }
}
static const char *export_kind_name(uint8_t k) {
  switch (k) { case 0: return "func"; case 1: return "table"; case 2: return "memory";
               case 3: return "global"; case 4: return "tag"; default: return "?"; }
}
static size_t align_up(size_t v, size_t a) { return (v + (a - 1)) & ~(a - 1); }

static const char *func_export_name(uint32_t i) {
  for (uint32_t k = 0; k < g_expn; k++) if (g_exp[k].index == i) return g_exp[k].name;
  return NULL;
}

static void decode_target_info(reader_t *r, size_t body, uint32_t size) {
  if (size < 48) { printf("      %s<target_info too small>%s\n", BADC, RST); return; }
  uint16_t bin_type = rd_u16_at(r, body + 0);
  uint16_t abi_type = rd_u16_at(r, body + 2);
  uint16_t e_type   = rd_u16_at(r, body + 4);
  uint16_t e_machine= rd_u16_at(r, body + 6);
  uint32_t e_version= rd_u32_at(r, body + 8);
  uint32_t e_flags  = rd_u32_at(r, body + 12);
  uint64_t feats    = rd_u64_at(r, body + 16);
  char arch[17]; memset(arch, 0, sizeof(arch));
  for (int i = 0; i < 16; i++) arch[i] = (char) rd_u8_at(r, body + 32 + i);
  g_is64 = (bin_type & 2) ? 1 : 0;
  g_machine = e_machine;
  printf("      %s%s%s, %s%s%s  abi=%u  e_type=%u  machine=%s0x%02x (%s)%s\n",
         BOLD, (bin_type & 1) ? "big-endian" : "little-endian", RST,
         BOLD, g_is64 ? "64-bit" : "32-bit", RST, abi_type, e_type,
         ARCH, e_machine, machine_name(e_machine), RST);
  printf("      e_version=%s%u%s  e_flags=0x%x  features=0x%016llx  arch=%s\"%s\"%s\n",
         NUM, e_version, RST, e_flags, (unsigned long long) feats, ARCH, arch, RST);
}

static void decode_export(reader_t *r, size_t body, uint32_t size) {
  size_t end = body + size, pos = body;
  uint32_t count = rd_u32_at(r, pos); pos += 4;
  if (r->err) { printf("      %s<export truncated>%s\n", BADC, RST); return; }
  printf("      %s%u%s export(s):\n", NUM, count, RST);
  for (uint32_t i = 0; i < count; i++) {
    pos = align_up(pos, 4);
    uint32_t index = rd_u32_at(r, pos); pos += 4;
    uint8_t  kind  = rd_u8_at(r, pos);  pos += 1;
    pos = align_up(pos, 2);
    uint16_t slen  = rd_u16_at(r, pos); pos += 2;
    if (r->err || pos + slen > end) { printf("        %s<export %u truncated>%s\n", BADC, i, RST); break; }
    char name[96];
    size_t n = slen < sizeof(name) ? slen : sizeof(name) - 1;
    for (size_t j = 0; j < n; j++) name[j] = (char) rd_u8_at(r, pos + j);
    name[n ? n - 1 : 0] = 0;
    pos += slen;
    printf("        [%u] %s%-6s%s index=%-3u  %s\"%s\"%s\n",
           i, DIM, export_kind_name(kind), RST, index, SYM, name, RST);
    if (kind == 0 && g_expn < MAXF) {
      g_exp[g_expn].index = index;
      snprintf(g_exp[g_expn].name, sizeof(g_exp[g_expn].name), "%s", name);
      g_expn++;
    }
  }
}

static uint32_t try_func_layout(reader_t *r, size_t body, uint32_t size, uint32_t extra) {
  uint32_t wsz = g_is64 ? 8 : 4;
  uint32_t entry = wsz + 4 + extra;
  if (entry == 0 || size % entry != 0) return 0;
  uint32_t fc = size / entry;
  if (fc == 0 || fc > MAXF) return 0;
  uint64_t prev = 0;
  for (uint32_t i = 0; i < fc; i++) {
    uint64_t o = g_is64 ? rd_u64_at(r, body + (size_t) i * 8)
                        : rd_u32_at(r, body + (size_t) i * 4);
    if (r->err || o >= g_code_size || (i > 0 && o < prev)) return 0;
    prev = o;
  }
  return fc;
}

static void decode_function(reader_t *r, size_t body, uint32_t size) {
  if (g_code_size == 0) { printf("      %s<no TEXT seen yet>%s\n", BADC, RST); return; }
  uint32_t wsz = g_is64 ? 8 : 4;
  uint32_t fc = try_func_layout(r, body, size, 0);
  if (!fc) fc = try_func_layout(r, body, size, 8);
  if (!fc) { printf("      %s<could not determine func_count>%s\n", BADC, RST); return; }

  for (uint32_t i = 0; i < fc; i++)
    g_foff[i] = g_is64 ? rd_u64_at(r, body + (size_t) i * 8)
                       : rd_u32_at(r, body + (size_t) i * 4);
  size_t tbase = body + (size_t) fc * wsz;
  for (uint32_t i = 0; i < fc; i++) g_ftype[i] = rd_u32_at(r, tbase + (size_t) i * 4);
  g_fcount = fc;
  printf("      %s%u%s function(s) (func index -> TEXT offset)\n", NUM, fc, RST);
}

static void print_symbol_table(void) {
  if (g_fcount == 0) return;
  printf("\n%s== functions (symbolized) ==%s   %s(text @ file 0x%x, assuming import_func_count=0)%s\n",
         TITLE, RST, DIM, g_text_foff, RST);
  for (uint32_t i = 0; i < g_fcount; i++) {
    uint64_t foff = g_foff[i];
    uint64_t fend = (i + 1 < g_fcount) ? g_foff[i + 1] : g_code_size;
    uint64_t fsz  = fend > foff ? fend - foff : 0;
    uint64_t file_off = (uint64_t) g_text_foff + foff;
    const char *nm = func_export_name(i);
    printf("  %s[%2u]%s text+0x%s%-6llx%s  file@0x%s%-6llx%s  size=%s%-4llu%s  type=%u  %s%s%s\n",
           DIM, i, RST,
           NUM, (unsigned long long) foff, RST,
           NUM, (unsigned long long) file_off, RST,
           NUM, (unsigned long long) fsz, RST, g_ftype[i],
           SYM, nm ? nm : "", RST);
  }
}

static uint8_t *read_file(const char *path, size_t *out_len) {
  FILE *fp = fopen(path, "rb");
  if (!fp) { perror(path); return NULL; }
  fseek(fp, 0, SEEK_END); long sz = ftell(fp); fseek(fp, 0, SEEK_SET);
  if (sz < 0) { fclose(fp); return NULL; }
  uint8_t *buf = malloc((size_t) sz ? (size_t) sz : 1);
  if (!buf) { fclose(fp); return NULL; }
  *out_len = fread(buf, 1, (size_t) sz, fp);
  fclose(fp);
  return buf;
}

int main(int argc, char **argv) {
  const char *path = NULL;
  int force_color = 0, no_color = 0;
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--color")) force_color = 1;
    else if (!strcmp(argv[i], "--no-color")) no_color = 1;
    else path = argv[i];
  }
  if (!path) { fprintf(stderr, "usage: %s [--color|--no-color] <file.aot>\n", argv[0]); return 2; }
  g_color = !no_color && (force_color || (isatty(fileno(stdout)) && !getenv("NO_COLOR")));

  size_t len = 0;
  uint8_t *buf = read_file(path, &len);
  if (!buf) return 1;
  reader_t r; rd_init(&r, buf, len);

  uint32_t magic = rd_u32_at(&r, 0), version = rd_u32_at(&r, 4);
  printf("%s== unaot: %s %s(%zu bytes)%s ==\n", TITLE, path, DIM, len, RST);
  printf("magic    : 0x%08x %s%s%s\n", magic,
         magic == AOT_MAGIC ? OKC : BADC,
         magic == AOT_MAGIC ? "(\\0aot ok)" : "(BAD - not a WAMR .aot)", RST);
  printf("version  : %s%u%s\n", NUM, version, RST);
  if (magic != AOT_MAGIC) { free(buf); return 1; }

  size_t p = 8; int n = 0;
  while (1) {
    p = align_up(p, 4);
    if (p + 8 > len) break;
    uint32_t type = rd_u32_at(&r, p), size = rd_u32_at(&r, p + 4);
    if (r.err) break;
    size_t body = p + 8;
    if (size > len - body) {
      printf("\n[%d] %s%s%s  %s<TRUNCATED>%s\n", n, SEC, sec_name(type), RST, BADC, RST);
      break;
    }
    printf("\n%s[%d]%s section %s%-18s%s type=%u  off=0x%s%zx%s  size=%s%u%s\n",
           DIM, n, RST, SEC, sec_name(type), RST, type, NUM, body, RST, NUM, size, RST);
    switch (type) {
      case AOT_SEC_TARGET_INFO: decode_target_info(&r, body, size); break;
      case AOT_SEC_TEXT:
        g_text_foff = (uint32_t) body; g_code_size = size;
        printf("      -> %snative machine code%s (%u bytes); disassemble per arch\n", BOLD, RST, size);
        break;
      case AOT_SEC_FUNCTION: decode_function(&r, body, size); break;
      case AOT_SEC_EXPORT:   decode_export(&r, body, size);   break;
      default: break;   /* RELOCATION: part 3 */
    }
    p = body + size; n++;
  }
  printf("\n%d sections.\n", n);
  print_symbol_table();
  free(buf);
  return 0;
}
```

### demo

We reuse the `add.aot` from part 1 (the two-function `add` / `fib` module):     

![aot](/assets/images/228/2026-10-11_15-16.png){:class="img-responsive"}   

Build:    

```bash
cc -std=c11 -O2 -Wall -o unaot unaot.c
```

![aot](/assets/images/228/2026-10-11_15-20.png){:class="img-responsive"}   

and run:     

```bash
./unaot add.aot
```

![aot](/assets/images/228/2026-10-11_15-21.png){:class="img-responsive"}    

![aot](/assets/images/228/2026-10-11_15-22.png){:class="img-responsive"}    

There it is - three native functions, each with a name, a file offset, and a size. The naive `60 / 12 = 5` trap is avoided: the validator picked the stack-frame layout and reported `3`. `add` is the 16 bytes at file offset `0x160`, `fib` the 56 bytes at `0x170`. You can `xxd -s 0x170 -l 56 add.aot` and you are looking at exactly the compiled `fib`.    

And just like in part 1, nothing here is architecture-specific. Run it on the `aarch64` build and you get the same three names mapped onto AArch64 code - only the sizes change, because the instruction encodings differ:    

```bash
./unaot add_aarch64.aot
```

![aot](/assets/images/228/2026-10-11_15-30.png){:class="img-responsive"}     

![aot](/assets/images/228/2026-10-11_15-30_1.png){:class="img-responsive"}     

One honest caveat, flagged right in the output. Our index-to-name join assumes `import_func_count == 0` - i.e. the module imports no host functions, so *defined* function index `i` equals *global* function index `i`. That holds for a self-contained module like this one, but a real firmware module usually imports host/WASI functions, which shifts all the defined indices. You can already see the symptom on a real sample: Sony's AITRIOS edge-app `.aot` files export `__main_argc_argv` at index `307` while only `289` functions are defined - the export indices are absolute and our table would mislabel them. Reading the true `import_func_count` out of `INIT_DATA` is the fix, and it is on the list.    

You may also have noticed the `RELOCATION` section sitting there, decoded only as far as "here it is." That is deliberate - relocations are how we recover *cross-references* between functions (including that recursive `fib` self-call), and they are the whole subject of part 3.   

### summary

| piece                  | what it does                                                        |
|------------------------|---------------------------------------------------------------------|
| `decode_export()`      | names mapped to function indices (WAMR string: u16 len incl. NUL)   |
| `decode_function()`    | function index mapped to TEXT offset + type; derives `func_count`   |
| `try_func_layout()`    | guesses the per-entry layout and validates it (sorted, in-range)    |
| `print_symbol_table()` | joins the two on the index -> name + file offset + size             |
| color helpers          | readable on a terminal, clean when piped (`NO_COLOR` aware)         |

We now turn an anonymous native blob into a named function table - the thing you actually load into a disassembler. In the *next part* we decode the `RELOCATION` section to recover cross-references between functions, and then wrap everything into a *Ghidra loader* so you can open a `.aot` straight into Ghidra with arch, code, symbols and xrefs already in place.     

I hope this post is useful for reverse engineers, embedded and IoT security researchers, and everyone curious about how WebAssembly really ships on devices.     

[WebAssembly Micro Runtime (WAMR)](https://github.com/bytecodealliance/wasm-micro-runtime)    
[WAMR AOT compiler (wamrc) and prebuilt releases](https://github.com/bytecodealliance/wasm-micro-runtime/releases)    
[reversing embedded WebAssembly: part 1](/reverse/2026/09/30/wasm-aot-reversing-1.html)   
[WebAssembly core specification](https://webassembly.github.io/spec/core/)   
[source code in github - part 2](https://github.com/cocomelonc/meow/tree/master/2026-10-12-wasm-aot-reversing-2)    

> This is a practical case for educational purposes only.

Thanks for your time happy hacking and good bye!     
*PS. All drawings and screenshots are mine*
