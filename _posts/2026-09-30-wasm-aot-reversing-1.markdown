---
title:  "Reversing embedded WebAssembly: part 1. Cracking the WAMR .aot container in pure C."
date:   2026-09-30 04:00:00 +0200
header:
  teaser: "/assets/images/226/2026-10-01_16-49.png"
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

![aot](/assets/images/226/2026-10-01_16-49.png){:class="img-responsive"}    

WebAssembly has quietly escaped the browser. On tiny devices - IoT sensors, edge gateways, automotive ECUs, even trusted execution environments - it now runs through small standalone engines, and the most popular of them is the **WebAssembly Micro Runtime** (`WAMR`), from the Bytecode Alliance. On a microcontroller you rarely ship a `.wasm` file and interpret it: it is too slow. Instead you run `WAMR`'s AOT compiler, `wamrc`, ahead of time and ship a `.aot` file - a native code blob wrapped in a `WAMR`-specific container.    

And here is the interesting part for a reverse engineer. Plain `.wasm` is very well tooled - `wabt`, `JEB`, Ghidra loaders, half a dozen decompilers. The proprietary `.aot` container that actually lands on the device has *no public tooling at all*. If you pull one out of a firmware image, you are on your own.    

So over the next few posts we will build that tooling from scratch, in pure C, one tiny dependency-free file. I called it `unaot`. This part 1 does the foundation: we *reverse the `.aot` container format* from real bytes and write a parser that walks its sections and tells us the target architecture. Parts 2 and 3 will recover function names, cross-references and finally a Ghidra loader.    

### the idea

A `.aot` file is not WebAssembly bytecode. `wamrc` runs the same LLVM backend a normal compiler uses and emits **native machine code** for a concrete target (`x86_64`, `aarch64`, `riscv`, `xtensa`...), then wraps that code together with the metadata the runtime needs to load and relocate it: a target descriptor, initialization data, a function table, exports, and a relocation table.

For us that means the "star" of the analysis is native code - but you cannot even find it until you parse the container that surrounds it. That container is undocumented outside the `WAMR` source, so step one is simply to read it byte by byte. Everything else in this series stands on that.

### practical example

Let's produce a real `.aot` to look at. We do not need a full `WAMR` build - `clang` already has a WebAssembly backend, and the Bytecode Alliance ships a prebuilt `wamrc` in their [releases](https://github.com/bytecodealliance/wasm-micro-runtime/releases). A two-function C file is enough:

```c
// add.c
int add(int a, int b) { return a + b; }
int fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }
```

First grab `wamrc` itself. It is not in your package manager - the Bytecode Alliance publishes a prebuilt binary with every release, so we just download and unpack the one for our OS (here Linux `x86_64`; there are macOS and Windows builds on the same [releases page](https://github.com/bytecodealliance/wasm-micro-runtime/releases)):

```bash
curl -L -o wamrc.tar.gz \
  https://github.com/bytecodealliance/wasm-micro-runtime/releases/download/WAMR-2.4.5/wamrc-2.4.5-x86_64-ubuntu-22.04.tar.gz
tar xzf wamrc.tar.gz        # -> ./wamrc
./wamrc --version
```

![wasm](/assets/images/226/2026-10-01_15-46.png){:class="img-responsive"}    

(If you prefer to build it from source, it lives in `wamr-compiler/` in the `WAMR` tree and needs LLVM - the prebuilt binary is far quicker for just following along.) Now compile the C to a `.wasm` module, then to a `.aot`:

```bash
clang --target=wasm32 -O2 -nostdlib -Wl,--no-entry -Wl,--export-all -o add.wasm add.c
./wamrc -o add.aot add.wasm
```

![wasm](/assets/images/226/2026-10-01_15-45.png){:class="img-responsive"}    

Now look at the first bytes of the result:

```bash
xxd -l 16 add.aot
```

![wasm](/assets/images/226/2026-10-01_15-48.png){:class="img-responsive"}    

There it is. The file starts with `00 61 6f74` - the ASCII string `\0aot`, a deliberate mirror of WebAssembly's own `\0asm` magic. The four bytes after it, `05 00 00 00`, are the format *version* - `5` for this `wamrc`. Then the sections begin.     

### the format

Cross-checking those bytes against `WAMR`'s `core/config.h` and `core/iwasm/aot/aot_loader.c` gives us the whole container. It is small and regular:    

```cpp
u32 magic     = 0x746f6100   ("\0aot")
u32 version
sections:  [ u32 type | u32 size | u8 body[size] ]   (repeated to EOF)
```

Each section is a type, a size, and a body of that many bytes. The type ids come straight from the runtime:

| id  | section       | contents                                              |
|-----|---------------|-------------------------------------------------------|
| 0   | TARGET_INFO   | arch / machine / endianness / word size               |
| 1   | INIT_DATA     | memory, table, globals, import info                   |
| 2   | TEXT          | *the native machine code*                             |
| 3   | FUNCTION      | per-function text offsets and type indices            |
| 4   | EXPORT        | exported names                                        |
| 5   | RELOCATION    | relocations to apply into TEXT / data                 |
| 6   | SIGNATURE     | reserved                                              |
| 100 | CUSTOM        | custom (names, native symbols)                        |

There is one non-obvious rule that will bite you if you miss it. `WAMR`'s loader reads every multi-byte value through an alignment-aware macro that first rounds the pointer up to the field's width. In practice this means **every section header starts on a 4-byte boundary** - the compiler inserts up to three padding bytes after a section body before the next header. Walk the file as a naive `type, size, skip size` loop and you desync on the very first odd-sized section. We will handle that with a single `align_up(pos, 4)`.    

The first section, `TARGET_INFO`, is the one we decode in part 1, because it tells us which CPU the `TEXT` code is for - without it the native blob is meaningless. Its 48-byte body is a fixed struct:    

| off | type     | field         | notes                                                           |
|-----|----------|---------------|-----------------------------------------------------------------|
| 0   | u16      | bin_type      | bit0: big-endian; bit1: 64-bit                                  |
| 2   | u16      | abi_type      |                                                                 |
| 4   | u16      | e_type        |                                                                 |
| 6   | u16      | e_machine     | ELF machine id: `0x3e` x86_64, `0xb7` aarch64, `0xf3` riscv...  |
| 8   | u32      | e_version     |                                                                 |
| 12  | u32      | e_flags       |                                                                 |
| 16  | u64      | feature_flags |                                                                 |
| 24  | u64      | reserved      |                                                                 |
| 32  | char[16] | arch          | NUL-terminated, e.g. `"x86_64"`, `"aarch64v8"`, `"riscv64"`     |

The `e_machine` field is just the ELF machine number, which is convenient - it is the same value you would read out of a normal ELF header, so once we have it we know exactly how to disassemble `TEXT` later.    

Let's look at the source code first. Two files. First a bounds-checked reader, `reader.h`. Every access is validated against the buffer end - this matters because `.aot` files come out of firmware you do not trust, and `WAMR`'s own AOT loader has had memory-safety CVEs. We never want *our* parser to be the second bug:     

```c
// reader.h - little-endian, bounds-checked
#include <stdint.h>
#include <stddef.h>

typedef struct { const uint8_t *base; size_t len, pos; int err; } reader_t;

static inline void rd_init(reader_t *r, const uint8_t *b, size_t n) {
  r->base = b; r->len = n; r->pos = 0; r->err = 0;
}
static inline int rd_ok(const reader_t *r, size_t off, size_t n) {
  return off <= r->len && n <= r->len - off;   /* no overflow */
}
static inline uint16_t rd_u16_at(reader_t *r, size_t o) {
  if (!rd_ok(r, o, 2)) { r->err = 1; return 0; }
  return (uint16_t)(r->base[o] | (r->base[o + 1] << 8));
}
static inline uint32_t rd_u32_at(reader_t *r, size_t o) {
  if (!rd_ok(r, o, 4)) { r->err = 1; return 0; }
  return (uint32_t)(r->base[o] | ((uint32_t)r->base[o+1] << 8)
                    | ((uint32_t)r->base[o+2] << 16) | ((uint32_t)r->base[o+3] << 24));
}
static inline uint64_t rd_u64_at(reader_t *r, size_t o) {
  if (!rd_ok(r, o, 8)) { r->err = 1; return 0; }
  return (uint64_t)rd_u32_at(r, o) | ((uint64_t)rd_u32_at(r, o + 4) << 32);
}
static inline uint8_t rd_u8_at(reader_t *r, size_t o) {
  if (!rd_ok(r, o, 1)) { r->err = 1; return 0; }
  return r->base[o];
}
```

The one idea here is `rd_ok`: it checks `n <= r->len - off` only *after* confirming `off <= r->len`, so the subtraction can never wrap around. A malformed section size can set `err`, but it can never make us read out of bounds.    

Now the parser, `unaot.c`. The constants and the two little lookup tables first:    

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "reader.h"

#define AOT_MAGIC 0x746f6100u   /* "\0aot" */

enum { SEC_TARGET_INFO=0, SEC_INIT_DATA=1, SEC_TEXT=2, SEC_FUNCTION=3,
       SEC_EXPORT=4, SEC_RELOCATION=5, SEC_SIGNATURE=6, SEC_CUSTOM=100 };

static const char *sec_name(uint32_t t) {
  switch (t) {
    case SEC_TARGET_INFO: return "TARGET_INFO"; case SEC_INIT_DATA: return "INIT_DATA";
    case SEC_TEXT: return "TEXT (native code)"; case SEC_FUNCTION: return "FUNCTION";
    case SEC_EXPORT: return "EXPORT"; case SEC_RELOCATION: return "RELOCATION";
    case SEC_SIGNATURE: return "SIGNATURE"; case SEC_CUSTOM: return "CUSTOM";
    default: return "<unknown>";
  }
}
static const char *machine_name(uint16_t m) {
  switch (m) {
    case 0x3e: return "x86_64"; case 0xb7: return "AArch64"; case 0xf3: return "RISC-V";
    case 0x28: return "ARM"; case 0x03: return "x86"; case 0xdc: return "Xtensa (ESP32)";
    default: return "<other>";
  }
}
static size_t align_up(size_t v, size_t a) { return (v + (a - 1)) & ~(a - 1); }
```

Decoding `TARGET_INFO` is a direct transcription of the struct above:     

```c
static void decode_target_info(reader_t *r, size_t body, uint32_t size) {
  if (size < 48) { printf("      <target_info too small>\n"); return; }
  uint16_t bin_type  = rd_u16_at(r, body + 0);
  uint16_t e_machine = rd_u16_at(r, body + 6);
  uint32_t e_version = rd_u32_at(r, body + 8);
  char arch[17] = {0};
  for (int i = 0; i < 16; i++) arch[i] = (char) rd_u8_at(r, body + 32 + i);
  printf("      %s, %s  machine=0x%02x (%s)  arch=\"%s\"  e_version=%u\n",
         (bin_type & 1) ? "big-endian" : "little-endian",
         (bin_type & 2) ? "64-bit" : "32-bit",
         e_machine, machine_name(e_machine), arch, e_version);
}
```

And `main` ties it together: slurp the file, verify the magic, then walk the section table - aligning to 4 before every header, and clamping every size against the buffer so a corrupt `.aot` degrades gracefully instead of crashing:    

```c
static uint8_t *read_file(const char *path, size_t *out_len) {
  FILE *fp = fopen(path, "rb");
  if (!fp) { perror(path); return NULL; }
  fseek(fp, 0, SEEK_END); long sz = ftell(fp); fseek(fp, 0, SEEK_SET);
  uint8_t *buf = malloc(sz > 0 ? sz : 1);
  *out_len = fread(buf, 1, (size_t) sz, fp);
  fclose(fp);
  return buf;
}

int main(int argc, char **argv) {
  if (argc < 2) { fprintf(stderr, "usage: %s <file.aot>\n", argv[0]); return 2; }
  size_t len = 0;
  uint8_t *buf = read_file(argv[1], &len);
  if (!buf) return 1;

  reader_t r; rd_init(&r, buf, len);
  uint32_t magic = rd_u32_at(&r, 0), version = rd_u32_at(&r, 4);

  printf("== unaot: %s (%zu bytes) ==\n", argv[1], len);
  printf("magic    : 0x%08x %s\n", magic,
         magic == AOT_MAGIC ? "(\\0aot ok)" : "(BAD - not a WAMR .aot)");
  printf("version  : %u\n\n", version);
  if (magic != AOT_MAGIC) { free(buf); return 1; }

  size_t p = 8; int n = 0;
  while (1) {
    p = align_up(p, 4);                 /* every section header is 4-aligned */
    if (p + 8 > len) break;
    uint32_t type = rd_u32_at(&r, p), size = rd_u32_at(&r, p + 4);
    if (r.err) break;
    size_t body = p + 8;
    if (size > len - body) { printf("[%d] %s <truncated>\n", n, sec_name(type)); break; }

    printf("[%d] section %-18s type=%u  off=0x%zx  size=%u\n",
           n, sec_name(type), type, body, size);
    if (type == SEC_TARGET_INFO) decode_target_info(&r, body, size);
    else if (type == SEC_TEXT)
      printf("      -> native machine code blob (%u bytes)\n", size);

    p = body + size; n++;
  }
  printf("\n%d sections.\n", n);
  free(buf);
  return 0;
}
```

That is the entire (for part 1, I will planning to write new parts with full features) tool - one header, one `.c`, no libraries.

Full source code:    

```cpp
/*
 * unaot.c
 * part 1: WAMR .aot container parser (header, sections, TARGET_INFO).
 * author: cocomelonc
 * https://cocomelonc.github.io/reverse/2026/09/30/wasm-aot-reversing-1.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "reader.h"

#define AOT_MAGIC 0x746f6100u   /* "\0aot" */

enum { SEC_TARGET_INFO=0, SEC_INIT_DATA=1, SEC_TEXT=2, SEC_FUNCTION=3,
       SEC_EXPORT=4, SEC_RELOCATION=5, SEC_SIGNATURE=6, SEC_CUSTOM=100 };

static const char *sec_name(uint32_t t) {
  switch (t) {
    case SEC_TARGET_INFO: return "TARGET_INFO"; case SEC_INIT_DATA: return "INIT_DATA";
    case SEC_TEXT: return "TEXT (native code)"; case SEC_FUNCTION: return "FUNCTION";
    case SEC_EXPORT: return "EXPORT"; case SEC_RELOCATION: return "RELOCATION";
    case SEC_SIGNATURE: return "SIGNATURE"; case SEC_CUSTOM: return "CUSTOM";
    default: return "<unknown>";
  }
}
static const char *machine_name(uint16_t m) {
  switch (m) {
    case 0x3e: return "x86_64"; case 0xb7: return "AArch64"; case 0xf3: return "RISC-V";
    case 0x28: return "ARM"; case 0x03: return "x86"; case 0xdc: return "Xtensa (ESP32)";
    default: return "<other>";
  }
}
static size_t align_up(size_t v, size_t a) { return (v + (a - 1)) & ~(a - 1); }

static void decode_target_info(reader_t *r, size_t body, uint32_t size) {
  if (size < 48) { printf("      <target_info too small>\n"); return; }
  uint16_t bin_type  = rd_u16_at(r, body + 0);
  uint16_t e_machine = rd_u16_at(r, body + 6);
  uint32_t e_version = rd_u32_at(r, body + 8);
  char arch[17] = {0};
  for (int i = 0; i < 16; i++) arch[i] = (char) rd_u8_at(r, body + 32 + i);
  printf("      %s, %s  machine=0x%02x (%s)  arch=\"%s\"  e_version=%u\n",
         (bin_type & 1) ? "big-endian" : "little-endian",
         (bin_type & 2) ? "64-bit" : "32-bit",
         e_machine, machine_name(e_machine), arch, e_version);
}

static uint8_t *read_file(const char *path, size_t *out_len) {
  FILE *fp = fopen(path, "rb");
  if (!fp) { perror(path); return NULL; }
  fseek(fp, 0, SEEK_END); long sz = ftell(fp); fseek(fp, 0, SEEK_SET);
  uint8_t *buf = malloc(sz > 0 ? sz : 1);
  *out_len = fread(buf, 1, (size_t) sz, fp);
  fclose(fp);
  return buf;
}

int main(int argc, char **argv) {
  if (argc < 2) { fprintf(stderr, "usage: %s <file.aot>\n", argv[0]); return 2; }
  size_t len = 0;
  uint8_t *buf = read_file(argv[1], &len);
  if (!buf) return 1;

  reader_t r; rd_init(&r, buf, len);
  uint32_t magic = rd_u32_at(&r, 0), version = rd_u32_at(&r, 4);

  printf("== unaot: %s (%zu bytes) ==\n", argv[1], len);
  printf("magic    : 0x%08x %s\n", magic,
         magic == AOT_MAGIC ? "(\\0aot ok)" : "(BAD - not a WAMR .aot)");
  printf("version  : %u\n\n", version);
  if (magic != AOT_MAGIC) { free(buf); return 1; }

  size_t p = 8; int n = 0;
  while (1) {
    p = align_up(p, 4);                 /* every section header is 4-aligned */
    if (p + 8 > len) break;
    uint32_t type = rd_u32_at(&r, p), size = rd_u32_at(&r, p + 4);
    if (r.err) break;
    size_t body = p + 8;
    if (size > len - body) { printf("[%d] %s <truncated>\n", n, sec_name(type)); break; }

    printf("[%d] section %-18s type=%u  off=0x%zx  size=%u\n",
           n, sec_name(type), type, body, size);
    if (type == SEC_TARGET_INFO) decode_target_info(&r, body, size);
    else if (type == SEC_TEXT)
      printf("      -> native machine code blob (%u bytes)\n", size);

    p = body + size; n++;
  }
  printf("\n%d sections.\n", n);
  free(buf);
  return 0;
}
```

### demo

Build it and point it at our `add.aot`:

```bash
cc -std=c11 -O2 -Wall -o unaot unaot.c
./unaot add.aot
```

![aot](/assets/images/226/2026-10-01_16-39.png){:class="img-responsive"}    

Six sections, ending exactly at end of file - proof the alignment handling is correct. We now know this blob is `x86_64`, that its native code lives at file offset `0x150` and is 88 bytes long, and where every other section sits.

The nicest part is that none of this is architecture-specific. Re-target the same module with 
```bash
wamrc --target=aarch64 -o add_aarch64.aot add.wasm
```

![aot](/assets/images/226/2026-10-01_16-41.png){:class="img-responsive"}    

and run `unaot` again:     

```bash
./unaot add_aarch64.aot
```

![aot](/assets/images/226/2026-10-01_16-42.png){:class="img-responsive"}    

Same parser, different CPU - because the container is identical across targets and only `TARGET_INFO` changes. The same holds for `riscv64` and 32-bit `arm`.     

### summary

| piece                  | what it does                                                    |
|------------------------|-----------------------------------------------------------------|
| `reader.h`             | little-endian reads that can set an error but never overrun     |
| magic + version check  | confirm `\0aot`, capture the format version                     |
| section walk           | `type / size / body`, 4-byte aligned, size-clamped              |
| `decode_target_info()` | arch, endianness, word size, ELF machine id                     |

One honest caveat before we move on: the `.aot` format is *versioned and strict*. A `WAMR` runtime loads only `.aot` files whose version equals its own, and the layout of the inner sections changes between versions. Version `5` is what a current `wamrc` emits, but the version you will most often meet in real, already-deployed firmware is `3` - it covers `WAMR` `1.0.0` all the way to `2.2.x`. Happily, the container, the section ids and this whole `TARGET_INFO` struct are byte-identical from version `3` to `6`, so everything in part 1 already generalizes. The differences live deeper, in the function and relocation bodies - which is exactly where we are going next.     

In the *next part* we decode the `FUNCTION` and `EXPORT` sections, turn the raw `TEXT` blob into a **symbolized function table** - every native function mapped to its name and offset - and add colored output, still in one small C file.      

I hope this post with a practical example is useful for reverse engineers, embedded and IoT security researchers, and everyone curious about how WebAssembly really ships on devices.      

[WebAssembly Micro Runtime (WAMR)](https://github.com/bytecodealliance/wasm-micro-runtime)    
[WAMR AOT compiler (wamrc) and prebuilt releases](https://github.com/bytecodealliance/wasm-micro-runtime/releases)    
[WebAssembly core specification](https://webassembly.github.io/spec/core/)     
[Bytecode Alliance - WAMR 2024 in review](https://bytecodealliance.org/articles/wamr-2024-summary)     
[source code in github - part 1](https://github.com/cocomelonc/meow/tree/master/2026-09-30-wasm-aot-reversing-1)     

> This is a practical case for educational purposes only.

Thanks for your time happy hacking and good bye!
*PS. All drawings and screenshots are mine*
