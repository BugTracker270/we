# Blackbox SELF decrypter for PS4 13.52 — port plan

**Goal:** decrypt `dec/1352/80010008.self` on the console, feed the result to
`80010008.py`, then decrypt `dec/80010002_kernel_14.00.self` **offline**.

**Reference implementation (cloned locally):** `ps5-selfdec-ref/`
— [Cryptogenic/PS5-SELF-Decrypter](https://github.com/Cryptogenic/PS5-SELF-Decrypter)
(Specter / @SpecterDev, Unlicense), which credits alexaltea's orbital work.

This is the tool the psdevwiki calls *"PS4 SELF Decrypter on PS4 by AlexAltea …
one can use his PS4 as a blackbox"*, generalised and documented.

---

## 1. Go/no-go results

### 1.1 Does 14.00 use the same key_revision as 13.52? — **YES (strong evidence)**

If the revision differed, the keys taken from 80010008 (13.52) could never
decrypt the 14.00 kernel, and the whole plan would be worthless. Compared the
two kernel SELFs directly:

```
80010002 Kernel 13.52   80010002 Kernel 14.00
magic        1d3d154f   1d3d154f
unknown @4   00010112   00010112
program_type 0xc01      0xc01
header_size  0x100      0x100
sig_size     0x1b0      0x1b0
num_segments 1          1
unknown @1a  0x22       0x22
seg[0] flags 0x40f      0x40f
header 0x00-0x20: only 2 bytes differ — 0x10/0x11, i.e. the file size
```

**The headers are byte-identical apart from the file size.** No revision or
keyset field differs. If 14.00 had bumped the keyset, that is where it would
show. Combined with the wiki's still-open `1 | 4 | 13.50-??.??` row, this is a
solid green light.

### 1.2 Is the protocol documented? — **YES, completely**

`ps5-selfdec-ref/include/authmgr.h` and `source/authmgr.c` give the exact
command codes, the exact argument structures, and the exact sequence.

### 1.3 Do the PS5 porting anchors exist in the 13.52 kernel image? — **NO**

The README's anchor-string method (`"sdt"`, `"SblDrvSendSx"`, `"req mtx"`,
`"req msg cv"`, `"invlgn"`, `"pmap"`) found **0 occurrences** in our 19 MB
`.data`/`.bss` dump. Those lock-name strings live in the arena, not `.bss` — the
8 MB arena window we dumped shows the same *class* of strings (`"idt mtx pid=16"`,
`"idt sx pid=16"`). So the anchor method needs arena coverage we do not yet have.

**This is why we should not port the mailbox driver.** See §3.

## 2. The protocol, authoritatively

From `authmgr.h`:

```c
#define SBL_FUNC_AUTHMGR_VERIFY_HEADER      0x01
#define SBL_FUNC_AUTHMGR_LOAD_SELF_SEGMENT  0x02
#define SBL_FUNC_AUTHMGR_FINALIZE           0x05
#define SBL_FUNC_AUTHMGR_LOAD_SELF_BLOCK    0x06
```

**Correct this against our own derivation:** the earlier disassembly-derived
`AUTHMGR_CMD_LOAD_SELF_BLOCK` value is **wrong** — the reference says `0x06`,
not `0x03`. Exactly the class of error the reference was needed to catch.

Each command payload is a **0x80-byte** struct whose first field is `function`:

```c
struct sbl_msg_header {            // 0x18
    uint32_t cmd;        // 0x00   == 6 for all AuthMgr calls
    uint16_t query_len;  // 0x04   == 0x80
    uint16_t recv_len;   // 0x06   == 0x80
    uint64_t message_id; // 0x08
    uint64_t to_ret;     // 0x10   == authmgr_handle
}; // size: 0x18

struct sbl_authmgr_verify_header { // size 0x80
    uint32_t function;         // 0x00
    uint32_t res;              // 0x04
    uint64_t self_header_pa;   // 0x08
    uint32_t self_header_size; // 0x10
    uint8_t  unk14[0x8];       // 0x14
    uint32_t service_id;       // 0x1C  <-- returned, needed by the next calls
    uint64_t auth_id;          // 0x20
    uint8_t  unk28[0x10];      // 0x28
    uint16_t unk38;            // 0x38
    uint8_t  pad[0x80 - 0x3A];
};

struct sbl_authmgr_load_segment {  // size 0x80
    uint32_t function;         // 0x00
    uint32_t res;              // 0x04
    uint64_t chunk_table_pa;   // 0x08
    uint32_t segment_index;    // 0x10
    uint16_t is_block_table;   // 0x14
    uint16_t unk16;            // 0x16
    uint8_t  unk18[0x18];      // 0x18
    uint32_t service_id;       // 0x30
    uint8_t  pad[0x80 - 0x34];
};

struct sbl_authmgr_load_block {    // size 0x80
    uint32_t function;         // 0x00
    uint32_t res;              // 0x04
    uint64_t out_pa;           // 0x08
    uint64_t in_pa;            // 0x10
    uint64_t unk18;            // 0x18
    uint64_t unk20;            // 0x20
    uint64_t unk28;            // 0x28
    uint32_t aligned_size;     // 0x30
    uint32_t size;             // 0x34
    uint32_t unk38;            // 0x38
    uint32_t segment_index;    // 0x3C
    uint32_t block_index;      // 0x40
    uint32_t service_id;       // 0x44
    uint8_t  digest[0x20];     // 0x48  copied from block_segment->digests[i]
    uint8_t  ext_info[0x8];    // 0x68  copied from block_segment->extents[i]
    uint16_t is_compressed;    // 0x70
    uint16_t unk72;            // 0x72
    uint16_t is_plain_elf;     // 0x74
    uint8_t  pad[0x80 - 0x76];
};

struct sbl_authmgr_finalize_ctx {  // size 0x80
    uint32_t function;         // 0x00
    uint32_t res;              // 0x04
    uint32_t context_id;       // 0x08
    uint8_t  pad[0x80 - 0x0C];
};
```

**Sequence:** `VERIFY_HEADER` (returns `service_id`) →
`LOAD_SELF_SEGMENT` per segment → `LOAD_SELF_BLOCK` per block (using
`service_id`) → `FINALIZE` (frees the context).

Segment flag maths (`self.h`) — needed to walk the segments ourselves:

```c
SELF_SEGMENT_IS_ENCRYPTED(x)  ((x->flags & (1 << 1)) != 0)
SELF_SEGMENT_IS_COMPRESSED(x) ((x->flags & (1 << 3)) != 0)
SELF_SEGMENT_HAS_BLOCKS(x)    ((x->flags & (1 << 11)) != 0)
SELF_SEGMENT_BLOCK_SIZE(x)    (1 << (((x->flags >> 12) & 0xF) + 0xC))
```

Applying that to our real files:

```
80010008 AuthMgr 13.52                       80010002 Kernel 13.52
[0] flags=0x6    off=0x13e0  size=0x10f9c      [0] flags=0x40f  off=0x2b0
[1] flags=0x100006 off=0x123e0 size=0x2d84         enc_comp=0xa5cb9c dec=0x14a65e8
[2] flags=0x200006 off=0x153e0 size=0x510
```

`0x6` = encrypted+signature, **not compressed, not blocked, not ordered** —
consistent with the wiki: *"Secure Modules besides Kernel are only signed and
encrypted but are not compressed, blocked or ordered"*. The kernel is `0x40f` =
ordered+encrypted+signature+deflated, not blocked.

**So 80010008's three segments are plain AES-CBC** — which makes it the
easiest possible target, and possibly means `LOAD_SELF_BLOCK` is not needed for
it at all. Worth testing both paths.

## 3. The port: use the kernel's own AuthMgr, do not rebuild the mailbox

The PS5 payload hand-rolls the SBL mailbox because it has no callable kernel API
conveniently available. `sceSblAuthMgrSmRequest` is **not used** — instead
`sbl.c` does everything manually:

1. read `mailbox_base` out of kernel memory
2. `mailbox_addr = mailbox_base + 0x800 * (0x10 + 0xE)`
3. `kernel_copyin(msg_header, mailbox_addr)`, `kernel_copyin(in_buf, mailbox_addr + 0x18, query_len)`
4. `mailbox_pa = pmap_kextract(mailbox_addr)`
5. `kernel_copyin(&mailbox_pa, mmio_space + 0x10568)` and
   `kernel_copyin(&(cmd << 8), mmio_space + 0x10564)`, where
   `mmio_space = dmap_base + 0xE0500000`
6. poll `mmio_space + 0x10564` until bit 0 set
7. `kernel_copyout(mailbox_addr + 0x18, out_buf, recv_len)`

That drags in 11 firmware-specific offsets (mailbox base/flags/meta/mtx, DMPML4I,
DMPDPI, PML4PML4I, authmgr handle, two datacaves) — and §1.3 shows the anchor
strings for finding them are **not** in our `.data`/`.bss` dump.

**We do not need any of that on PS4.**

We already have, confirmed on hardware:

| Piece | Value | Status |
|---|---|---|
| kernel base | `0xffffffff85680000` (ASLR-slid, read at runtime) | working |
| `sceSblAuthMgrSmRequest` | koff `0x63FFF0`, `(ctx, cmd, _, in, out)` | derived from disassembly |
| AuthMgr context table | koff `0x269C140`, 4 × 0x60 | **hardware-confirmed** |
| ctx state / index / buffer | `+0x00`=2, `+0x30`=idx, `+0x38`=buffer | **hardware-confirmed** |
| SM started | `SM_FLAG @0x269c098 = 1` | **hardware-confirmed** |
| kernel R/W | `kexec` (syscall 11) + `get_memory_dump`, 4 KiB chunks | **proven on 19 MB** |

So the PS4 payload should **let the kernel do the mailbox work**: call
`sceSblAuthMgrSmRequest(ctx, function_code, 0, &arg_in, &arg_out)` with the
0x80-byte structs above. That eliminates the mailbox offsets, the MMIO poke, the
dmap base, the PML4 indices and the authmgr-handle anchor — i.e. essentially the
entire porting surface the PS5 README warns about.

## 4. Remaining unknowns, ranked

1. **Arg2 semantics.** `(ctx rdi, arg esi, _, auth_info_in rcx, auth_info_out r8)`
   is a disassembly-derived guess, not documentation. Is `arg` the function code
   (1/2/5/6), or something else? This is the single biggest unknown.
2. **VA vs PA for the data buffers.** The PS5 structs carry *physical* addresses
   (`self_header_pa`, `chunk_table_pa`, `in_pa`, `out_pa`) because the SM DMAs.
   Whether the kernel's own `sceSblAuthMgrSmRequest` accepts kernel VAs and
   converts internally is **unverified**. If it needs PAs, we need
   `pmap_kextract` (findable in the decrypted kernel ELF) or the dmap base.
3. **Is `ctx` a handle or a pointer into the table?** The PS5 README notes the
   authmgr handle is "usually 0x4" — but our derived handle read `0`. Our
   hardware-confirmed table has 4 live entries with `state=2`, so a pointer to
   `0x269C140` (or `0x269C1A0` etc.) is the natural candidate.
4. **Chunk table construction.** `LOAD_SELF_SEGMENT` wants a chunk table
   (`sbl_chunk_table_header` 0x20 + entries 0x10 each). Its construction is in
   `ps5-selfdec-ref/source/main.c` (27 KB, not yet read) — read that next.

## 5. Expect this to cost reboots

Straight from the reference README, and worth taking at face value:

> *"If you notice log activity has stopped for more than a minute, hard powerdown
> the console via power button for three beeps and restart … The console may
> panic in the midst of dumping files, this is fine, restart the console and run
> again. The payload will pick up where it left off."*

So the reference tool itself panics consoles and is designed around it. Two
protections to build in from the start:

- **Work on a copy, and make every step resumable** — the payload should record
  which segments/blocks are already decrypted to a file on USB, so a panic costs
  one block, not the run.
- **Never call `_sceSblAuthMgrSmStart`** (koff `0x63E470`). It is already
  responsible for both of this project's console kills.

## 6. Immediate next actions

1. Read `ps5-selfdec-ref/source/main.c` — the chunk-table construction and the
   block-iteration loop, which is the bulk of the algorithm.
2. Resolve unknown #1 (`arg2`) by disassembling `sceSblAuthMgrSmRequest` in the
   decrypted 13.52 kernel (`czdji0/1352k.elf`) and reading what it actually does
   with `esi` — that file is on disk, so this is offline and free.
3. Only then write the payload.

---

# 7. Disassembly of koff 0x63FFF0 — unknowns #1 and #3 resolved

Sliced straight out of `czdji0/1352k.elf` (objdump refused the ELF itself, so I
resolved VA→file offset from its own program headers and disassembled the raw
bytes as flat x86-64). Function prologue is at `0xffffffff8283fff0` =
`kbase + 0x63FFF0`.

## 7.1 Our offsets are confirmed a third time — now from code

```asm
ffffffff8284000d:  mov    %rdi,%r12            ; arg1 saved  (the context)
ffffffff8284000b:  mov    %esi,%ebx            ; arg2 saved  (the command!)
ffffffff8284001b:  mov    %rcx,%r15            ; arg4 saved  (in-auth-info)
ffffffff82840018:  mov    %r8,%r14             ; arg5 saved  (out-auth-info)
ffffffff82840015:  mov    %r8,%rdi
ffffffff82840010:  mov    $0x88,%esi
ffffffff82840025:  call   ...                 ; memset(out, 0, 0x88)
ffffffff8284002a:  lea    -0xb0(%rbp),%rdi
ffffffff82840031:  mov    $0x80,%esi
ffffffff82840036:  call   ...                 ; memset(msg, 0, 0x80)
ffffffff8284003b:  movw   $0x16,-0xb0(%rbp)   ; msg.function = 0x16
ffffffff82840044:  mov    %ebx,-0xa8(%rbp)    ; msg[+0x08] = arg2   <-- THE COMMAND
```

Then:

```asm
ffffffff828400d5:  mov    $0x88,%edx
ffffffff828400da:  mov    %r12,%rdi
ffffffff828400dd:  mov    %r15,%rsi
ffffffff828400e0:  call   0xffffffff824bd5a0  ; memcpy(dst, in_auth_info, 0x88)

ffffffff828400fe:  mov    0x205bf9b(%rip),%rdi  # 0xffffffff8489c0a0   <-- !!
ffffffff82840105:  lea    -0xb0(%rbp),%rdx
ffffffff8284010c:  mov    %rdx,%rsi
ffffffff8284010f:  call   0xffffffff82830230  ; the mailbox send
```

Resolve those absolute addresses against `kbase = 0xffffffff82200000`:

| Instruction address | koff | offset table name | verdict |
|---|---|---|---|
| `0xffffffff8489c0a0` | `0x269C0A0` | `KO_1352_AUTHMGR_HANDLE` | **confirmed in code** |
| `0xffffffff8489c0b0` | `0x269C0B0` | `KO_1352_AUTHMGR_BUF_A` | **confirmed in code** |
| `0xffffffff8489c0c0` | `0x269C0C0` | `KO_1352_AUTHMGR_BUF_B` | **confirmed in code** |
| `0xffffffff8489c0c8` | `0x269C0C8` | SM mtx | **confirmed — it is locked** |
| `0xffffffff8489c0e8` | `0x269C0E8` | second lock | **confirmed — used as sx** |

The kernel reads the authmgr handle from `kbase+0x269C0A0` itself and hands it to
the mailbox call. That is exactly the field our probe read as `0` — so **`0` is
not a broken read, it is genuinely the handle this kernel passes.** The shell
loads SELFs all day with it.

And the lock is taken on the *address* `kbase+0x269C0C8`:

```asm
ffffffff828400f4:  xor    %esi,%esi
ffffffff828400f6:  mov    %r15,%rdi          ; r15 = 0xffffffff8489c0c8  (ADDRESS)
ffffffff828400f9:  call   0xffffffff822a3840 ; mtx_lock
...
ffffffff82840114:  mov    %r15,%rdi
ffffffff8284011a:  mov    $0x54d,%edx
ffffffff82840121:  call   0xffffffff822a3a00 ; mtx_unlock
```

**This is the lock v6's `_sceSblAuthMgrSmStart` grabbed and never released.** Now
we know precisely which one, and that the payload only has to *call* this
function — the kernel takes and releases the lock itself, correctly.

## 7.2 Unknown #1 — `arg2` is the command. Resolved.

`arg2` (`esi`) is stored into the message at `+0x08`, and the message's own
`+0x00` is a fixed `0x16` (the SBL opcode for an AuthMgr request). So:

```c
sceSblAuthMgrSmRequest(ctx, command, /*unused*/ 0, &auth_info_in, &auth_info_out)
```

with `command` ∈ { `0x01` VERIFY_HEADER, `0x02` LOAD_SELF_SEGMENT,
`0x05` FINALIZE, `0x06` LOAD_SELF_BLOCK } from `authmgr.h`.

The reply is validated as `u16 == 0x16` at `+0x00` and the return value is the
**u32 at `+0x04`**:

```asm
ffffffff8284012a:  movzwl -0xb0(%rbp),%ecx
ffffffff82840131:  cmp    $0x16,%ecx
ffffffff82840134:  jne    ...                ; bad reply
ffffffff82840136:  mov    -0xac(%rbp),%ecx   ; reply[+0x04]
ffffffff8284013c:  test   %ecx,%ecx
ffffffff8284013e:  je     ...                ; success, returns it
```

That `+0x04` u32 is what comes back as `service_id` — which is why the reference
implementation threads `service_id` from `VERIFY_HEADER` into every later call.
The mechanism now matches the reference exactly.

## 7.3 Unknown #3 — the context argument

`arg1` is dereferenced as a struct, not an opaque handle:

```asm
ffffffff8284007d:  mov    0x1c(%r12),%eax   ; ctx->field_0x1c
ffffffff82840085:  mov    %eax,-0xa0(%rbp) ; into msg[+0x10]
ffffffff82840097:  cmpl   $0x1,(%r12)      ; ctx->field_0x00 == 1 ?
ffffffff8284009c:  sete   %al
ffffffff828400a1:  mov    %ax,-0x9c(%rbp)  ; into msg[+0x14]
```

`ctx->field_0x00` is our `CTX_OFF_STATE` (reads 2), and `+0x1C` is a further
field. **So `arg1` is a pointer to a context entry** — i.e. `kbase + 0x269C140 +
(i * 0x60)` for one of the four live entries. Not a handle, not an index.

## 7.4 The structs are 0x88 bytes, not 0x80

```asm
ffffffff82840025:  call ... ; memset(out, 0, 0x88)
ffffffff828400d5:  mov $0x88,%edx
ffffffff828400e0:  call ... ; memcpy(dst, in, 0x88)
```

And `0x88` is exactly `SELF_AUTH_INFO_SIZE` — the size of the auth-info blob in
the SELF itself. So the in/out arguments are **the SELF's auth_info structure**,
not the PS5 payload's `sbl_authmgr_*` structs. That is a meaningful difference
from the reference: the PS5 code wraps its own 0x80-byte structs in a 0x18-byte
message header, whereas the PS4 kernel function takes the 0x88-byte auth_info
directly and builds the message itself.

**Consequence:** the next piece of work is the **0x88-byte `self_auth_info`
layout**, not the PS5 structs. It lives in the SELF we already have, at
`header_size` onwards, and `self.h` in the reference plus
`SELF_AUTH_INFO_SIZE 0x88` in the offset table pin its size. Fields to identify:
the four `*_pa` members the SM DMAs against, and `service_id` at the reply's
`+0x04`.

## 7.5 Revised remaining unknowns

| # | Unknown | Status |
|---|---|---|
| 1 | `arg2` semantics | **RESOLVED** — it is the command |
| 3 | ctx as handle vs pointer | **RESOLVED** — it is a pointer to a ctx entry |
| 5 | argument struct size | **RESOLVED** — 0x88 bytes = the SELF auth_info |
| 2 | VA vs PA inside the struct | **OPEN** — the SM DMAs, so likely still PAs; needs `pmap_kextract` or a datacave in the dmap |
| 4 | 0x88 auth_info field map | **OPEN** — read it out of `80010008.self` at `header_size` |
| 6 | chunk table for non-blocked segments | **OPEN** — but 80010008 has no blocked segments, which simplifies it |

Both remaining opens are offline work. No console time needed yet.

---

# 8. The reference is PS4-native — and the port is small

`orbital-ref/tools/dumper/` (AlexAltea, MIT) is a **PS4** tool, not a port
target. `source/self_decrypter.c` (611 lines) is the whole algorithm, and
`source/ksdk_sbl.h` gives every structure. `source/ksdk_176/455/500/505.inc` are
per-firmware offset tables — which is exactly the shape of the job: supply a
13.52 table.

## 8.1 Same execution mechanism we already use

```c
int self_verify_header(self_t *self) { syscall(11, self_kverify_header, self); return 0; }
```

`syscall(11, fn, arg)` — **that is `kexec`**, the same primitive our kmemdump
payload uses, and the same one libPS4 wraps. The reference runs the AuthMgr
protocol in kernel context through it. No new capability required.

## 8.2 The address problem is solved by the kernel, not by us

```c
kassert(!sceSblDriverMapPages(&header_data_mapped, header_data, 1, 0x61, NULL, &header_data_mapdesc));
...
args->header_addr = header_data_mapped;
```

The SM needs a *bus* address, and the reference obtains it with
**`sceSblDriverMapPages()`** — it does not use `pmap_kextract` and does not need
a dmap base or PML4 indices. That closes unknown #2 from §7.5.

It also locks around the mailbox call:

```c
#define sceSblServiceMailbox_locked(ret, id, iptr, optr) do { \
        _sx_xlock(authmgr_sm_xlock, 0, NULL, 0);              \
        ret = sceSblServiceMailbox((id), (iptr), (optr));      \
        _sx_xunlock(authmgr_sm_xlock, NULL, 0);                \
    } while (0)
```

## 8.3 Symbol table: 5.05 → 13.52

Reference requirements from `ksdk_505.inc`, matched against what is already
confirmed on our console.

| symbol | 5.05 koff | 13.52 koff | status |
|---|---|---|---|
| `sceSblServiceMailbox(module_id, query, reply)` | `0x00632540` | **`0x00630230`** | ✅ **have** — and our own disassembly showed the AuthMgr wrapper *calling* `0xffffffff82830230` |
| `sceSblAuthMgrModuleId` | `0x02768310` | **`0x0269C0A0`** | ✅ **have** — disassembly reads this value and passes it as the mailbox id |
| `authmgr_sm_xlock` | `0x027680D0` | **`0x0269C0C8`** | ✅ **have** — disassembly `mtx_lock`s exactly this address |
| `self_contexts` | `0x02768150` | **`0x0269C140`** | ✅ **have** — hardware-confirmed, stride `0x60`, `self_context_t` fields decode |
| `self_ctx_status` | `0x02768140` | **`0x0269C130`** | ✅ **have** — reads `[3,3,3,3]`, and `3` is the reference's "free" value |
| `mtx_lock` / `mtx_unlock` | *(uses sx)* | **`0x000A3840` / `0x000A3A00`** | ✅ **have** — both call targets in our disassembly |
| `_sceSblAuthMgrSmFinalize` | `0x00642840` | `0x0063FF00` | ⚠️ derived, needs confirm |
| `sceSblDriverMapPages` | `0x0061BD90` | — | ❌ **need** (in the `0x61xxxx` SBL-driver cluster) |
| `sceSblDriverUnmapPages` | `0x0061C460` | — | ❌ **need** (0x6D0 after MapPages on 5.05) |
| `kmalloc(size, area, flags)` | `0x0010E250` | — | ❌ **need** |
| `kfree(ptr, area)` | `0x0010E460` | — | ❌ **need** |
| `M_AUTHMGR` (malloc area) | `0x01A727E0` | — | ❌ **need** |
| `make_chunk_table` / `map_chunk_table` | `0x00630400` / `0x006303B0` | — | ✅ **not needed** — build the table ourselves (§8.4) |
| `_sx_xlock` / `_sx_xunlock` | `0x000F5E10` / `0x000F5FD0` | — | ✅ **not needed** if we lock 13.52's own mtx at `0x269C0C8` |

**Corrections to `offsets_1352.h` that came out of this:**

- `CTX_OFF_INDEX = 0x30` is really **`buf_id`** (reference field name); the value
  reads 0/1/2/3 so the earlier guess was reasonable but the meaning was wrong.
- `CTX_OFF_BUFFER = 0x38` is really **`header`** — a `self_header_t*`, and the
  four pointers are `0x1000` apart. Same conclusion, right offset, wrong name.
- `CTX_OFF_STATE = 0x00` is **`format`** (reads 2 = ELF), not "state".
- New: **`self_ctx_status = 0x0269C130`**, `uint32_t[4]`, `3` = free.
- `KO_1352_FN_LOAD_SELF_BLOCK`'s old value `0x3` for the block command is
  **wrong** — the working command is `0x06`.

## 8.4 We do not need `make_chunk_table`

`ksdk_sbl.h` documents the structure completely:

```c
typedef struct sbl_authmgr_chunk_entry_t { uint64_t data_addr; uint64_t data_size; } ;
typedef struct sbl_authmgr_chunk_table_t {
    uint64_t data_addr;    // 0x00
    uint64_t data_size;    // 0x08
    uint64_t num_entries;  // 0x10
    uint64_t reserved;     // 0x18
    sbl_authmgr_chunk_entry_t entries[0];  // 0x20
} ;
```

We can build that by hand and map it with `sceSblDriverMapPages`, removing two
more symbol dependencies.

## 8.5 The command structures, exactly

From `ksdk_sbl.h` — these are 0x80 bytes, passed as **both** query and reply:

```c
#define AUTHMGR_CMD_VERIFY_HEADER        0x01
#define AUTHMGR_CMD_LOAD_SELF_SEGMENT    0x02
#define AUTHMGR_CMD_LOAD_SELF_BLOCK      0x06

typedef struct sbl_authmgr_verify_header_t {   // 0x80
    uint32_t function;      // 0x00
    uint32_t status;        // 0x04   <- checked == 0
    uint64_t header_addr;   // 0x08   <- bus addr from MapPages
    uint32_t header_size;   // 0x10   header_size + meta_size
    uint32_t zero_0C;       // 0x14
    uint32_t zero_10;       // 0x18
    uint32_t context_id;    // 0x1C   <- IN: our ctx; OUT: auth_ctx_id
    uint64_t auth_info_addr;// 0x20
    uint32_t unk_20;        // 0x28
    uint32_t key_id;        // 0x2C
    uint8_t  key[0x10];     // 0x30
};  // 0x40 used, padded to 0x80

typedef struct sbl_authmgr_load_self_segment_t {  // 0x80
    uint32_t function;         // 0x00
    uint32_t status;           // 0x04
    uint64_t chunk_table_addr; // 0x08
    uint32_t segment_index;    // 0x10
    uint32_t is_block_table;   // 0x14
    uint64_t zero_10;          // 0x18
    uint64_t zero_18;          // 0x20
    uint32_t zero_20;          // 0x28
    uint32_t zero_24;          // 0x2C
    uint32_t context_id;       // 0x30
};

typedef struct sbl_authmgr_load_self_block_t {  // 0x80
    uint32_t function;        // 0x00
    uint32_t status;          // 0x04
    uint64_t pages_addr;      // 0x08  (OUT)
    uint32_t segment_index;   // 0x10
    uint32_t context_id;      // 0x14
    uint8_t  digest[0x20];    // 0x18
    uint8_t  extent[0x8];     // 0x38
    uint32_t block_index;     // 0x40
    uint32_t data_offset;     // 0x44
    uint32_t data_size;       // 0x48
    uint64_t data_start_addr; // 0x50 (IN)
    uint64_t data_end_addr;   // 0x58
    uint32_t zero;            // 0x60
};
```

Context acquisition, from the reference:

```c
#define SELF_MAX_CONTEXTS 4
if (self->ctx_id == -1) {
    ctx_id = 0;
    while (self_ctx_status[ctx_id] != 3)          // 3 == free
        ctx_id = (ctx_id + 1) % SELF_MAX_CONTEXTS;
    self_ctx_status[ctx_id] = 1;                  // mark in use
    self->ctx_id = ctx_id;
}
self->ctx = &self_contexts[self->ctx_id];
_sceSblAuthMgrSmFinalize(self->ctx);
self->svc_id = *sceSblAuthMgrModuleId;
```

## 8.6 Good news for our specific target

`80010008`'s segment props are `0x6`, `0x100006`, `0x200006` — i.e. signed +
encrypted only. Bits 11 (`BLOCKED`), 16 (`HAS_DIGESTS`) and 17 (`HAS_EXTENTS`)
are **all clear**.

The reference's `self_load_segments()` only walks segments with digests/extents
or the blocked flag, so on its own it would do *nothing* for our file. For
80010008 the whole job reduces to `VERIFY_HEADER`, then one
`LOAD_SELF_SEGMENT` per segment with `is_block_table = 0`, copying each
segment's plaintext back out. **No block loop, no block table, no digests.**
That is the simplest possible case in this format, and it is exactly the target
we picked.

## 8.7 Remaining work, in order

1. Derive `sceSblDriverMapPages` / `UnmapPages` in the `0x61xxxx` cluster (we
   have `sceSblServiceMailbox` there as an anchor, plus 5.05's relative layout).
2. Derive `kmalloc` / `kfree` / `M_AUTHMGR` — or avoid `kmalloc` entirely by
   using a validated spare region of kernel `.bss`, found in the 19 MB dump we
   already have.
3. Confirm `_sceSblAuthMgrSmFinalize = 0x0063FF00`.
4. Write the payload: `syscall(11, ...)` in, kernel-context AuthMgr protocol,
   4 KiB `get_memory_dump` out.
5. Test on `80010008.self` (13.52, key_revision 1.4 — guaranteed to pass the
   console's own checks).
6. `80010008.py` → key banks → decrypt `80010002_kernel_14.00.self` **offline**.
