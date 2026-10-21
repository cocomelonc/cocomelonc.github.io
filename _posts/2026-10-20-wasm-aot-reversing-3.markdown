---
title:  "Reversing embedded WebAssembly: part 3. Recovering native cross-references from WAMR relocations in pure C."
date:   2026-10-20 04:00:00 +0200
header:
  teaser: "/assets/images/229/2026-10-21_19-31.png"
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

![aot](/assets/images/229/2026-10-21_19-31.png){:class="img-responsive"}     

In [part 2](/reverse/2026/10/12/wasm-aot-reversing-2.html), we joined `FUNCTION` and `EXPORT` to recover names for the native functions in a WAMR `.aot` file. Now we can locate `fib`. The next question is: *where does it reference another function, and which function is that?*     

This time we decode `RELOCATION`: its symbol table, string buffer, groups, and individual records. Then we connect a patch location to its containing function and resolve targets such as `aot_func#2`. The result is a native cross-reference: `fib -> fib`. Still C, still no external libraries.     

I am giving the Ghidra handoff its own fourth part. The series now has four steps:     

| part | result |
|------|--------|
| 1 | container sections and target architecture |
| 2 | function offsets and exported names |
| 3 | relocation records and native cross-references |
| 4 | bring the code, names, and references into Ghidra |

For this example I keep the same compiler as before: `wamrc 2.4.5`, producing AOT format version `5`. The parser below deliberately accepts that version and little-endian ELF relocatable targets. The format description follows the release's [AOT emitter](https://raw.githubusercontent.com/bytecodealliance/wasm-micro-runtime/WAMR-2.4.5/core/iwasm/compilation/aot_emit_aot_file.c).     

### practical example

We reuse our small module:     

```c
// add.c
int add(int a, int b) { return a + b; }
int fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }
```

If you already have `add.aot` from part 2, keep it. To rebuild it with the `wamrc` from part 1:     

```bash
./wamrc --version
clang --target=wasm32 -O2 -nostdlib -Wl,--no-entry -Wl,--export-all -o add.wasm add.c
./wamrc -o add.aot add.wasm
```

The listings below use the supplied sample. Rebuilding it here with Clang `19.1.7` and `wamrc 2.4.5` produced the same AOT bytes; other compiler versions or options can change the offsets.     

![aot compilation](/assets/images/229/2026-10-21_18-50.png){:class="img-responsive"}     

### first, correct the native-code base

Before recovering references, there is a correction to part 2. We treated the `TEXT` section body as the start of native code. In this format the body actually begins with a literal-size field:     

```bash
TEXT body:
    u32 literal_size
    u8  literals[literal_size]
    u8  code[remaining bytes]

code_file_offset = TEXT_body_file_offset + 4 + literal_size
```

The [release loader's `load_text_section()`](https://raw.githubusercontent.com/bytecodealliance/wasm-micro-runtime/WAMR-2.4.5/core/iwasm/aot/aot_loader.c) advances past that prefix before using function offsets. Our sample has `literal_size = 0`, but the four-byte field is still present. The code begins at `0x154`, not `0x150`. Consequently, the file offsets printed in part 2 were four bytes early: `add` starts at `0x164` and `fib` at `0x174`.     

Also, the distance to the next function offset is a *span*, which can include alignment padding. For the last function, our upper bound is the remaining code region. We should not call either value an exact machine-code size.     

### the RELOCATION layout

Section type `5` has two pieces. First comes a symbol directory:     

```bash
u32 symbol_count
u32 symbol_offsets[symbol_count]
u32 total_string_len
u8  string_buffer[total_string_len]

each symbol_offsets[i] points inside string_buffer:
    u16 length
    u8  bytes[length]    // terminating NUL is included
```

An index selects an entry in `symbol_offsets[]`; that entry selects a length-prefixed string. It does not point directly into the file. Group names such as `.rela.text` and target names such as `aot_func#2` share this directory.     

After the string buffer, aligned to four bytes, come the groups:     

```bash
u32 group_count
repeat group_count:
    u32 group_name_index
    u32 relocation_count
    repeat relocation_count:
        word offset
        word addend
        u32  relocation_type
        u32  symbol_index
```

Here `word` is `u64` for a 64-bit target and `u32` for a 32-bit target. That choice comes from `TARGET_INFO`, not the architecture of the computer running `unaot`. A record therefore occupies `24` or `16` bytes. The emitter aligns these records to **four bytes, including their 64-bit fields**. Rounding them to eight desynchronizes this very sample.     

`offset` is relative to the region named by the group. For a text group it is a location in native code. `addend` is a signed adjustment represented in that target-width word. `relocation_type` describes the architecture-specific operation; the number `4` does not mean the same thing on every CPU.     

### step 1: read within section boundaries

We reuse `reader.h` from part 1. Each section now gets its own reader view, so a corrupt relocation cannot consume bytes belonging to a following section. This small helper advances the cursor only after checking both alignment padding and data:     

```c
static size_t take(reader_t *r, size_t n, size_t alignment) {
  size_t pad = (alignment - r->pos % alignment) % alignment;
  if (r->err || !rd_ok(r, r->pos, pad)) { r->err = 1; return 0; }
  r->pos += pad;
  if (!rd_ok(r, r->pos, n)) { r->err = 1; return 0; }
  size_t at = r->pos;
  r->pos += n;
  return at;
}
```

The target-width read uses four-byte alignment in both cases:     

```c
static uint64_t word(reader_t *r) {
  size_t p = take(r, g_is64 ? 8 : 4, 4);
  if (r->err) return 0;
  return g_is64 ? rd_u64_at(r, p) : rd_u32_at(r, p);
}
```

The updated `decode_text()` reads the literal length, checks that it fits, and saves the correct file base:     

```c
uint32_t literals = u32(r);
take(r, literals, 1);
if (r->err) return 0;
g_code_file = body + r->pos;
g_code_size = r->len - r->pos;
```

### step 2: resolve symbol indices

The string buffer gets a separate reader too. `reloc_symbol()` checks the index before accessing the offset directory, then checks that the offset stays inside that buffer:     

```c
static const char *reloc_symbol(reader_t *r, size_t offsets,
                                reader_t strings, uint32_t count, uint32_t idx) {
  if (idx >= count) { r->err = 1; return NULL; }
  uint32_t off = rd_u32_at(r, offsets + (size_t)idx * 4);
  if (r->err || off % 2 || !rd_ok(&strings, off, 2)) {
    r->err = 1; return NULL;
  }
  strings.pos = off;
  const char *s = string(&strings);
  if (strings.err) r->err = 1;
  return r->err ? NULL : s;
}
```

`string()` validates the two-byte length, the complete byte range, and the counted final NUL. It returns a pointer into the input buffer, which remains alive until parsing finishes. Names are not silently truncated into a smaller local array.     

The start of `decode_relocations()` gathers this directory and checks every symbol before processing groups:     

```c
uint32_t count = u32(r);
if (r->err || count > r->len / 4) return 0;
size_t offsets = take(r, (size_t)count * 4, 4);
uint32_t total = u32(r);
size_t start = take(r, total, 1);
if (r->err) return 0;
reader_t strings;
rd_init(&strings, r->base + start, total);
for (uint32_t i = 0; i < count; i++)
  if (!reloc_symbol(r, offsets, strings, count, i)) return 0;
```

### step 3: recover the source and target functions

For `.text`, `.rel.text`, and `.rela.text`, we locate the source by finding the function span containing the relocation offset:     

```c
static int func_at(uint64_t off) {
  for (uint32_t i = 0; i < g_fcount; i++) {
    uint64_t end = i + 1 < g_fcount ? g_foff[i + 1] : g_code_size;
    if (off >= g_foff[i] && off < end) return (int)i;
  }
  return -1;
}
```

For our recursive call, `off = 0x3b` lies in the span beginning at `0x20`, which belongs to defined function `2`: `fib`.     

The target symbol is `aot_func#2`. That suffix is a **defined-function index**, so it addresses `g_foff[2]` directly. We validate the entire decimal suffix and require it to be in range. Its target is code offset `0x20`, or file offset `0x154 + 0x20 = 0x174`.     

Export names use a different index space: they include imported functions. This version therefore accepts `--imports N`. For our self-contained module, `--imports 0` is known to be correct. If the import count is unknown, omit the option: references still use `aot_func#N`, and the tool leaves export names unresolved instead of assuming zero imports. Reading that count directly from `INIT_DATA` remains future work.     

### step 4: walk the records

For each group, the full program resolves its name and checks that `relocation_count` fits in the remaining section bytes. The record itself is small:     

```c
uint64_t off = word(r), raw_addend = word(r);
uint32_t type = u32(r), idx = u32(r);
const char *name = reloc_symbol(r, offsets, strings, count, idx);
if (r->err || (text && off >= g_code_size)) return 0;

int from = text ? func_at(off) : -1;
int to = defined_symbol(name);
```

We print the relocation type, signed addend, target symbol, patch location, and containing function. When the target is a defined function, we also print its name and file address. References to runtime helpers or data stay visible as symbolic targets.     

That target file address is the function symbol's base. The addend stays separate; interpreting the final referenced address still requires the relocation type.     

A relocation is not automatically a call. The output records references; we still inspect the instruction before describing a particular edge as a recursive call. It also does not represent a complete call graph: inline code and indirect calls require additional analysis.     

### full source code

Now the complete program (`unaot.c`). Keep the unchanged `reader.h` from part 1 beside it; both files are included in the companion source directory. The section table is collected first, then decoded in dependency order: target, code, functions, exports, relocations.     

```c
/*
 * unaot.c - part 3: WAMR AOT v5 relocations and native-code xrefs.
 * author: cocomelonc
 * https://cocomelonc.github.io/reverse/2026/10/20/wasm-aot-reversing-3.html
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include "reader.h"

#define MAXF 8192
#define COLOR(s) (g_color ? (s) : "")
#define RESET COLOR("\x1b[0m")
#define TITLE COLOR("\x1b[1;36m")
#define SYMBOL COLOR("\x1b[1;35m")
static int g_color, g_is64, g_imports_known;
static uint16_t g_machine;
static uint32_t g_imports, g_fcount, g_expn;
static size_t g_code_file, g_code_size;
static uint64_t g_foff[MAXF];
static uint32_t g_ftype[MAXF];
static struct { uint32_t index; const char *name; } g_exp[MAXF];
typedef struct { size_t body; uint32_t size; int seen; } section_t;

/* All sequential reads are confined to the current section. */
static size_t take(reader_t *r, size_t n, size_t alignment) {
  size_t pad = (alignment - r->pos % alignment) % alignment;
  if (r->err || !rd_ok(r, r->pos, pad)) { r->err = 1; return 0; }
  r->pos += pad;
  if (!rd_ok(r, r->pos, n)) { r->err = 1; return 0; }
  size_t at = r->pos;
  r->pos += n;
  return at;
}
static uint16_t u16(reader_t *r) {
  size_t p = take(r, 2, 2);
  return r->err ? 0 : rd_u16_at(r, p);
}
static uint32_t u32(reader_t *r) {
  size_t p = take(r, 4, 4);
  return r->err ? 0 : rd_u32_at(r, p);
}
static uint64_t word(reader_t *r) {
  size_t p = take(r, g_is64 ? 8 : 4, 4); /* u64 is only 4-aligned! */
  if (r->err) return 0;
  return g_is64 ? rd_u64_at(r, p) : rd_u32_at(r, p);
}
static const char *string(reader_t *r) {
  uint16_t n = u16(r);
  size_t p = take(r, n, 1);
  if (r->err || n == 0) { r->err = 1; return NULL; }
  const char *s = (const char *)r->base + p;
  if (s[n - 1] != '\0' || memchr(s, '\0', n - 1)) {
    r->err = 1; return NULL;
  }
  return s;
}

static const char *function_name(uint32_t i, char fallback[32]) {
  if (g_imports_known)
    for (uint32_t k = 0; k < g_expn; k++)
      if (g_exp[k].index >= g_imports && g_exp[k].index - g_imports == i)
        return g_exp[k].name;
  snprintf(fallback, 32, "aot_func#%u", i);
  return fallback;
}
static int func_at(uint64_t off) {
  for (uint32_t i = 0; i < g_fcount; i++) {
    uint64_t end = i + 1 < g_fcount ? g_foff[i + 1] : g_code_size;
    if (off >= g_foff[i] && off < end) return (int)i;
  }
  return -1;
}
static int defined_symbol(const char *s) {
  const char *prefix = "aot_func#";
  if (strncmp(s, prefix, strlen(prefix))) return -1;
  s += strlen(prefix);
  if (*s < '0' || *s > '9') return -1;
  uint32_t n = 0;
  for (; *s; s++) {
    if (*s < '0' || *s > '9') return -1;
    uint32_t digit = (uint32_t)(*s - '0');
    if (n > (UINT32_MAX - digit) / 10) return -1;
    n = n * 10 + digit;
  }
  return n < g_fcount ? (int)n : -1;
}
static const char *reloc_type(uint32_t t) {
  if (g_machine == 3) switch (t) {
    case 1: return "R_386_32";
    case 2: return "R_386_PC32";
    case 4: return "R_386_PLT32";
  }
  if (g_machine == 0x3e) switch (t) {
    case 1: return "R_X86_64_64";
    case 2: return "R_X86_64_PC32";
    case 4: return "R_X86_64_PLT32";
    case 9: return "R_X86_64_GOTPCREL";
    case 41: return "R_X86_64_GOTPCRELX";
    case 42: return "R_X86_64_REX_GOTPCRELX";
  }
  if (g_machine == 0xb7) switch (t) {
    case 257: return "R_AARCH64_ABS64";
    case 275: return "R_AARCH64_ADR_PREL_PG_HI21";
    case 277: return "R_AARCH64_ADD_ABS_LO12_NC";
    case 282: return "R_AARCH64_JUMP26";
    case 283: return "R_AARCH64_CALL26";
  }
  if (g_machine == 0xf3) switch (t) {
    case 2: return "R_RISCV_64";
    case 18: return "R_RISCV_CALL";
    case 19: return "R_RISCV_CALL_PLT";
    case 23: return "R_RISCV_PCREL_HI20";
    case 24: return "R_RISCV_PCREL_LO12_I";
  }
  return "unknown relocation";
}

static int decode_target(reader_t *r) {
  if (r->len < 48) return 0;
  uint16_t bin = rd_u16_at(r, 0), type = rd_u16_at(r, 4);
  if ((bin != 0 && bin != 2) || type != 1) {
    fputs("need a little-endian ELF relocatable AOT target\n", stderr);
    return 0;
  }
  g_is64 = (bin == 2);
  g_machine = rd_u16_at(r, 6);
  printf("target: %.*s, %u-bit, machine=0x%x\n", 16,
         (const char *)r->base + 32, g_is64 ? 64 : 32, g_machine);
  return !r->err;
}
static int decode_text(reader_t *r, size_t body) {
  uint32_t literals = u32(r);
  take(r, literals, 1);
  if (r->err) return 0;
  g_code_file = body + r->pos;
  g_code_size = r->len - r->pos;
  printf("TEXT: body@0x%zx, literal_size=%u, code@0x%zx, code span=%zu\n",
         body, literals, g_code_file, g_code_size);
  return 1;
}
static uint32_t try_functions(reader_t *r, uint32_t extra) {
  uint32_t wsz = g_is64 ? 8 : 4;
  if (r->len % (wsz + 4 + extra)) return 0;
  size_t count = r->len / (wsz + 4 + extra);
  if (count == 0 || count > MAXF) return 0;
  uint64_t previous = 0;
  for (size_t i = 0; i < count; i++) {
    uint64_t off = g_is64 ? rd_u64_at(r, i * wsz) : rd_u32_at(r, i * wsz);
    if (r->err || off >= g_code_size || (i && off < previous)) return 0;
    previous = off;
  }
  return (uint32_t)count;
}
static int decode_functions(reader_t *r) {
  if (r->len == 0) { g_fcount = 0; return 1; }
  uint32_t basic = try_functions(r, 0), frames = try_functions(r, 8);
  if ((!basic && !frames) || (basic && frames)) {
    fputs("unsupported or ambiguous FUNCTION layout\n", stderr); return 0;
  }
  g_fcount = basic ? basic : frames;
  for (uint32_t i = 0; i < g_fcount; i++) g_foff[i] = word(r);
  for (uint32_t i = 0; i < g_fcount; i++) g_ftype[i] = u32(r);
  if (frames) take(r, (size_t)g_fcount * 8, 4);
  return !r->err && r->pos == r->len;
}
static int decode_exports(reader_t *r) {
  uint32_t count = u32(r);
  if (r->err || count > r->len / 8) return 0;
  for (uint32_t i = 0; i < count; i++) {
    uint32_t index = u32(r);
    size_t p = take(r, 1, 1);
    uint8_t kind = r->err ? 0 : rd_u8_at(r, p);
    const char *name = string(r);
    if (r->err) return 0;
    if (kind == 0) {
      if (g_expn == MAXF) return 0;
      g_exp[g_expn].index = index;
      g_exp[g_expn++].name = name;
    }
  }
  return 1;
}
static void print_functions(void) {
  printf("\n%s== defined functions ==%s\n", TITLE, RESET);
  if (!g_imports_known) puts("export names unresolved: supply --imports N if known");
  for (uint32_t i = 0; i < g_fcount; i++) {
    char buf[32];
    uint64_t end = i + 1 < g_fcount ? g_foff[i + 1] : g_code_size;
    printf("[%u] code+0x%" PRIx64 " file@0x%" PRIx64
           " span=%" PRIu64 " type=%u %s%s%s\n", i, g_foff[i],
           (uint64_t)g_code_file + g_foff[i], end - g_foff[i], g_ftype[i],
           SYMBOL, function_name(i, buf), RESET);
  }
}

static const char *reloc_symbol(reader_t *r, size_t offsets,
                                reader_t strings, uint32_t count, uint32_t idx) {
  if (idx >= count) { r->err = 1; return NULL; }
  uint32_t off = rd_u32_at(r, offsets + (size_t)idx * 4);
  if (r->err || off % 2 || !rd_ok(&strings, off, 2)) {
    r->err = 1; return NULL;
  }
  strings.pos = off;
  const char *s = string(&strings);
  if (strings.err) r->err = 1;
  return r->err ? NULL : s;
}
static int decode_relocations(reader_t *r) {
  uint32_t count = u32(r);
  if (r->err || count > r->len / 4) return 0;
  size_t offsets = take(r, (size_t)count * 4, 4);
  uint32_t total = u32(r);
  size_t start = take(r, total, 1);
  if (r->err) return 0;
  reader_t strings;
  rd_init(&strings, r->base + start, total);
  for (uint32_t i = 0; i < count; i++)
    if (!reloc_symbol(r, offsets, strings, count, i)) return 0;
  uint32_t groups = u32(r);
  if (r->err || groups > (r->len - r->pos) / 8) return 0;
  printf("\n%s== relocations ==%s\n%u symbols, %u group(s)\n",
         TITLE, RESET, count, groups);
  for (uint32_t i = 0; i < groups; i++) {
    uint32_t name_idx = u32(r), n = u32(r);
    const char *group = reloc_symbol(r, offsets, strings, count, name_idx);
    size_t entry = g_is64 ? 24 : 16;
    if (r->err || n > (r->len - r->pos) / entry) return 0;
    int text = !strcmp(group, ".text") || !strcmp(group, ".rel.text")
               || !strcmp(group, ".rela.text");
    printf("group %s: %u relocation(s)\n", group, n);
    for (uint32_t j = 0; j < n; j++) {
      uint64_t off = word(r), raw_addend = word(r);
      uint32_t type = u32(r), idx = u32(r);
      const char *name = reloc_symbol(r, offsets, strings, count, idx);
      if (r->err || (text && off >= g_code_size)) return 0;
      unsigned bits = g_is64 ? 64 : 32;
      uint64_t sign = UINT64_C(1) << (bits - 1);
      uint64_t mask = g_is64 ? UINT64_MAX : UINT32_MAX;
      int negative = (raw_addend & sign) != 0;
      uint64_t magnitude = negative ? ((~raw_addend + 1) & mask) : raw_addend;
      printf("  off=0x%" PRIx64 " %s(%u) -> %s%s%s add=%s%" PRIu64,
             off, reloc_type(type), type, SYMBOL, name, RESET,
             negative ? "-" : "", magnitude);
      int from = text ? func_at(off) : -1;
      int to = defined_symbol(name);
      if (text) printf(" file@0x%" PRIx64, (uint64_t)g_code_file + off);
      if (from >= 0) {
        char a[32], b[32];
        printf(" | %s+0x%" PRIx64 " -> %s",
               function_name((uint32_t)from, a), off - g_foff[from],
               to >= 0 ? function_name((uint32_t)to, b) : name);
        if (to >= 0)
          printf(" [target file@0x%" PRIx64 "]", (uint64_t)g_code_file + g_foff[to]);
      }
      putchar('\n');
    }
  }
  return !r->err && r->pos == r->len;
}

static uint8_t *read_file(const char *path, size_t *len) {
  FILE *f = fopen(path, "rb");
  if (!f) { perror(path); return NULL; }
  if (fseek(f, 0, SEEK_END)) { fclose(f); return NULL; }
  long n = ftell(f);
  if (n < 0 || fseek(f, 0, SEEK_SET)) { fclose(f); return NULL; }
  uint8_t *buf = malloc(n ? (size_t)n : 1);
  if (!buf) { fclose(f); return NULL; }
  *len = fread(buf, 1, (size_t)n, f);
  int good = *len == (size_t)n && !ferror(f);
  fclose(f);
  if (!good) { free(buf); return NULL; }
  return buf;
}
int main(int argc, char **argv) {
  const char *path = NULL;
  g_color = isatty(STDOUT_FILENO) && !getenv("NO_COLOR");
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--no-color")) g_color = 0;
    else if (!strcmp(argv[i], "--color")) g_color = 1;
    else if (!strcmp(argv[i], "--imports") && i + 1 < argc) {
      const char *s = argv[++i];
      if (!*s) return 1;
      uint32_t n = 0;
      for (; *s; s++) {
        if (*s < '0' || *s > '9' || n > (UINT32_MAX - (uint32_t)(*s - '0')) / 10)
          return 1;
        n = n * 10 + (uint32_t)(*s - '0');
      }
      g_imports = n; g_imports_known = 1;
    } else if (argv[i][0] == '-' || path) return 1;
    else path = argv[i];
  }
  if (!path) {
    fprintf(stderr, "usage: %s [--no-color|--color] [--imports N] file.aot\n", argv[0]);
    return 1;
  }
  size_t len;
  uint8_t *buf = read_file(path, &len);
  if (!buf) return 1;
  reader_t file;
  rd_init(&file, buf, len);
  section_t sec[6] = {0};
  int ok = 0;
  if (u32(&file) != 0x746f6100u || u32(&file) != 5 || file.err) {
    fputs("need a WAMR AOT version 5 file\n", stderr); goto done;
  }
  while (file.pos < file.len) {
    uint32_t type = u32(&file), size = u32(&file);
    size_t body = take(&file, size, 1);
    if (file.err) goto done;
    if (type < 6) {
      if (sec[type].seen) goto done;
      sec[type] = (section_t){body, size, 1};
    }
  }
  reader_t r[6];
  for (int i = 0; i < 6; i++) {
    if (!sec[i].seen) goto done;
    rd_init(&r[i], buf + sec[i].body, sec[i].size);
  }
  if (!decode_target(&r[0]) || !decode_text(&r[2], sec[2].body)
      || !decode_functions(&r[3]) || !decode_exports(&r[4])) goto done;
  print_functions();
  ok = decode_relocations(&r[5]);
done:
  if (!ok) fputs("invalid, truncated, or unsupported AOT input\n", stderr);
  free(buf);
  return ok ? 0 : 1;
}
```

### demo

Compile it:     

```bash
cc -std=c11 -O2 -Wall -Wextra -Wpedantic -o unaot unaot.c
```

![aot](/assets/images/229/2026-10-21_18-53.png){:class="img-responsive"}     


Then run:     

```bash
./unaot --no-color --imports 0 add.aot
```

For the x86-64 sample, the output is:     

![aot](/assets/images/229/2026-10-21_18-54.png){:class="img-responsive"}     

That last line is the result we wanted: a patch in `fib` references `fib` itself. But look carefully at `file@0x18f`. Is that the beginning of a call instruction?     

### checking the actual instruction

Inspect five bytes starting one byte earlier:     

```bash
xxd -g 1 -s 0x18e -l 5 add.aot
```

![aot](/assets/images/229/2026-10-21_18-54_1.png){:class="img-responsive"}     

`e8` is the opcode for an x86 relative call. The relocation points to its four-byte displacement field, one byte after the opcode. So we have three different locations:     

| item | code-relative offset | file offset |
|------|----------------------|-------------|
| start of `fib` | `0x20` | `0x174` |
| call instruction | `0x3a` | `0x18e` |
| relocation patch field | `0x3b` | `0x18f` |

Confusing the last two would produce an xref into the middle of an instruction in a disassembler. This matters when we build the Ghidra handoff.     

Carve the corrected native region and disassemble it:     

```bash
dd if=add.aot of=text.bin bs=1 skip=340 count=84 status=none
objdump -D -b binary -m i386:x86-64 text.bin
```

![aot](/assets/images/229/2026-10-21_18-55.png){:class="img-responsive"}      

![aot](/assets/images/229/2026-10-21_18-56.png){:class="img-responsive"}      

![aot](/assets/images/229/2026-10-21_18-56_1.png){:class="img-responsive"}      

The unrelocated instruction displays a call to `0x3f`, because its displacement is still zero. The native bytes alone do not yet express the intended recursive target. For this internal reference, [WAMR's x86-64 relocation implementation](https://raw.githubusercontent.com/bytecodealliance/wasm-micro-runtime/WAMR-2.4.5/core/iwasm/aot/arch/aot_reloc_x86_64.c) uses the symbol address, addend, and patch address:     

```bash
displacement = S + A - P
             = 0x20 + (-4) - 0x3b
             = -0x1f

after relocation: e8 e1 ff ff ff
next instruction 0x3f + (-0x1f) = 0x20 = fib
```

The common code base cancels out in that subtraction. External helper symbols can involve runtime addresses or PLT entries; this calculation is specifically for the internal `fib` reference. Our parser reports metadata and leaves the input file unchanged.     

Also notice that the C expression contains two recursive calls, while the compiled sample has one recursive call relocation. In this build, the second recursive branch becomes a loop with an accumulator. That is a compiler transformation, not a missing relocation entry.     

### the same reference on another CPU

Compile the same Wasm module for AArch64:     

```bash
./wamrc --target=aarch64 -o add_aarch64.aot add.wasm
```

![aot](/assets/images/229/2026-10-21_19-14.png){:class="img-responsive"}     

check:    

```bash
./unaot --no-color --imports 0 add_aarch64.aot
```

![aot](/assets/images/229/2026-10-21_19-14_1.png){:class="img-responsive"}     

As you can see, the code layout changes, but the reference still resolves.     

Here the patch is in an AArch64 branch instruction, so the x86 "subtract one byte" observation does not apply. The container parser handles the metadata; interpreting and applying a relocation requires the target architecture.     

The RISC-V build works with the same parser too:     

```bash
./wamrc --target=riscv64 -o add_riscv64.aot add.wasm
```

![aot](/assets/images/229/2026-10-21_19-16.png){:class="img-responsive"}     

```bash
./unaot --no-color --imports 0 add_riscv64.aot
```

![aot](/assets/images/229/2026-10-21_19-16_1.png){:class="img-responsive"}     

I checked these three targets and an i386 build, which exercises 32-bit record fields. A separate one-import fixture verified the `--imports 1` name join. For the small x86-64 sample, all `860` shorter file prefixes were rejected, and targeted corrupt symbol offsets, indices, counts, strings, and code offsets were rejected under AddressSanitizer and UndefinedBehaviorSanitizer. These checks cover the demonstrated parser behavior, not every WAMR format variant.     

### side quest: a real device, and a bug in my own assumption

While finishing part 2 I pointed an earlier build of this tool at real firmware: the Sony [aitrios-sdk-edge-app 1.1.6](https://github.com/SonySemiconductorSolutions/aitrios-sdk-edge-app/releases/tag/1.1.6) edge applications, which ship prebuilt AArch64 `.aot` at AOT format version `3`. They parsed, and the section table looked healthy. But the exported names did not line up with the code, and the bug was in my tool, not in the files.

Here is the relevant part of `edge_app_passthrough.arm64.aot`:

![aot](/assets/images/229/2026-10-21_19-22.png){:class="img-responsive"}     

Look at `__main_argc_argv`: export index `277`, while `FUNCTION` declares only `258` functions. If an export index addressed a defined function directly, `277` would be out of range. It is valid only because imported host functions are numbered first. WAMR numbers functions as imported `0 .. import_func_count-1`, then defined functions after them. `EXPORT` uses that global index; `FUNCTION` uses the defined-only index. My part-2 code had quietly assumed `import_func_count == 0`. That is true for our self-contained `add.aot`, so the bug was invisible there, and real for anything that calls the host.

To reproduce it without the vendor binary, part 3 includes a one-import fixture, `import.c`:

```c
// import.c
__attribute__((import_module("env"), import_name("host_tick")))
extern int host_tick(int);
int use_tick(int n) { return host_tick(n) + 1; }
int bounce(int n) { return n <= 0 ? use_tick(n) : bounce(n - 1) + use_tick(n); }
```

One imported function, two defined, plus the compiler's `__wasm_call_ctors`. I keep both behaviors in the shipped tool, so the difference is visible. `--imports 0` reproduces the old assumption:

```bash
./unaot --no-color --imports 0 import.aot
```

![aot](/assets/images/229/2026-10-21_19-24.png){:class="img-responsive"}     

Every name is shifted by one slot. `__wasm_call_ctors` lands on `use_tick`'s function, `use_tick` lands on `bounce`'s, and the real `bounce` loses its name. The relocation view inherits the mistake: the recursive self-call of `bounce` prints as `use_tick -> use_tick`. Confident, and wrong.

The fix is to stop assuming. Subtract a known import count, and when the count is unknown, say so instead of guessing:

```bash
./unaot --no-color import.aot          # count unknown
```

![aot](/assets/images/229/2026-10-21_19-26.png){:class="img-responsive"}     

```bash
./unaot --no-color --imports 1 import.aot
```

![aot](/assets/images/229/2026-10-21_19-27.png){:class="img-responsive"}     

With the correct count the names land on the right functions and `bounce -> bounce` is the true recursion. With no count the tool prints `aot_func#N` and tells you why, rather than emitting plausible but wrong names. For reverse engineering that is the safer default: an honest "unknown" beats a confident mislabel. Reading `import_func_count` straight out of `INIT_DATA` would remove the flag entirely; that parse is on the list for later. The lesson is an ordinary one: a convenient assumption was true for my test input and false in the field, and only a real device surfaced it.    

### summary

| piece | what it adds |
|-------|--------------|
| corrected `TEXT` base | skip the literal-size field and literal region |
| section-local readers | confine reads to the relevant section or string buffer |
| `reloc_symbol()` | symbol index -> validated name |
| `func_at()` | patch location -> containing function span |
| `defined_symbol()` | `aot_func#N` -> defined-function target |
| `--imports N` | join known global export indices to defined functions |
| relocation output | source, target, type, addend, and file locations |

The main limitations remain explicit. We support format version `5` and ordinary little-endian ELF AOT targets. Function counts still come from the two candidate layouts discussed in part 2; if both validate, the parser rejects the ambiguous result. Export names require a known import count, and function spans can include padding. Only the three listed text-group names receive code-location mapping; other groups are printed without pretending they belong to a function.     

![aot](/assets/images/229/2026-10-21_19-31.png){:class="img-responsive"}     

![aot](/assets/images/229/2026-10-21_19-33.png){:class="img-responsive"}     

In part 4 we will bring this information into Ghidra: map the correct native code region, choose its processor, create named functions, and place references on the appropriate instructions. The `e8` example shows why copying relocation offsets directly into a disassembler is not enough.     

I hope this post is useful for reverse engineers, embedded and IoT security researchers, and everyone curious about how WebAssembly really ships on devices.     

[WAMR 2.4.5 release](https://github.com/bytecodealliance/wasm-micro-runtime/releases/tag/WAMR-2.4.5)     
[WAMR 2.4.5 AOT loader](https://raw.githubusercontent.com/bytecodealliance/wasm-micro-runtime/WAMR-2.4.5/core/iwasm/aot/aot_loader.c)     
[WAMR 2.4.5 AOT emitter](https://raw.githubusercontent.com/bytecodealliance/wasm-micro-runtime/WAMR-2.4.5/core/iwasm/compilation/aot_emit_aot_file.c)     
[reversing embedded WebAssembly: part 1](/reverse/2026/09/30/wasm-aot-reversing-1.html)     
[reversing embedded WebAssembly: part 2](/reverse/2026/10/12/wasm-aot-reversing-2.html)     
[source code in github - part 3](https://github.com/cocomelonc/meow/tree/master/2026-10-20-wasm-aot-reversing-3)     

> This is a practical case for educational purposes only.

Thanks for your time happy hacking and good bye!     
*PS. All drawings and screenshots are mine*
