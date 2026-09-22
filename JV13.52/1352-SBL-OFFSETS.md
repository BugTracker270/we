# PS4 13.52 — SBL/AuthMgr offsets for a blackbox SELF decrypter

Every value below was recovered from the **decrypted 13.52 kernel ELF**
(`C:\Users\Kinan\Downloads\czdji0\1352k.elf`, 20,080,104 B, two PT_LOADs:
`koff 0x0..0xcfe758` R-X, `koff 0x1520000..0x2834af0` RW-).

`koff` is the offset from `kernel_base` (`0xffffffff82200000` static, ASLR-slid
at runtime; read it from LSTAR). For the first PT_LOAD **`koff == file offset`**,
because that segment has `p_offset == 0`.

Purpose: drive the console's own AuthMgr secure module so a SELF can be
decrypted on the console (a legitimate blackbox use — the SELF keys are not
public, and the console's own module is the only implementation of them).
First target is `80010008` (the AuthMgr module) because its SELF key bank is
what lets the **14.00** kernel SELF be decrypted offline afterwards.

---

## 1. Calibration — proving the image really is 13.52

Before trusting anything derived here, the image was checked against libPS4's
own known-good `K1352_*` constants (`sdk/fw_defines.h`). All 17 land on the
expected code/data:

| symbol | K505 | K1352 | byte at K1352 |
|---|---|---|---|
| `XFAST_SYSCALL` | `0x000001c0` | `0x000001c0` | `0f 01 f8 65 48 89 24 25` (swapgs) |
| `ICC_NVS_WRITE` | `0x000A5A10` | `0x000A5A10` | `55 48 89 e5` |
| `COPYOUT` | `0x001EA630` | `0x002BD6A0` | `55 48 89 e5 65 48 8b 04` |
| `NPDRM_OPEN` | `0x0064D800` | `0x0064DF00` | `55 48 89 e5` |
| `NPDRM_IOCTL` | `0x0064D877` | `0x0064DF77` | mid-function, as expected |
| `PRISON_0` | `0x010986A0` | `0x0111FA18` | not file-backed → `.bss` |
| `ROOTVNODE` | `0x022C1A70` | `0x02136E90` | not file-backed → `.bss` |

`COPYOUT = 0x002BD6A0` is load-bearing: libPS4's own kernel-dump path calls it,
and the disassembly below confirms it is `copyout(kaddr, uaddr, len)`.

---

## 2. The five symbols that were missing

The orbital PS4 reference (`orbital-ref/tools/dumper/`, AlexAltea, MIT) needs
exactly these in addition to what was already confirmed.

### 2.1 `sceSblDriverMapPages` = **`0x0061AE20`**

Found by string xref, then confirmed three independent ways.

* The log string `"sceSblDriverMapPages %d"` sits at `koff 0x00AE624D` in
  `.rodata`, inside a cluster of SBL-driver strings
  (`W:\Build\J02697906\sys\internal\modules\sbl\driver\handler.c`,
  `SblDrvHdlrSx`, `SblDrvSendSx`, `SblDrvTskQ`).
* Two real **call sites** carry the error log
  `"ERROR: %s(%d) sceSblDriverMapPages %d"` (`koff 0x00AE9428`):
  * site `0x00627A08` — the call at `0x006279F9` targets `0x0061AE20`, and the
    argument setup immediately before it is
    `and rsi, 0xffffffffffffc000` / `and edx, 0x3fff` /
    `add rdx, 0x4007` / `shr rdx, 0xe`
    — i.e. page-align a VA and compute `npages = (len + 0x3fff) >> 14`.
  * site `0x00635C18` — `mov ecx, 0x61` / `mov edx, 1` / `xor r8d, r8d` then
    `call 0x0061AE20`. That is **byte-for-byte the reference's own call**:
    `sceSblDriverMapPages(&mapped, cpu_vaddr, 1, 0x61, NULL, &mapdesc)`.
* Its own body matches the 6-argument shape and the descriptor layout:
  `kmalloc(0x50, M_SBLDRV, flags)` for the descriptor, then
  `kmalloc(npages << 5, M_SBLDRV, flags)` for the page table, stored at
  `[desc+0x28]` and `[desc+0x48]`; `npages == 0` returns `0xffffffea` (EINVAL).

Cross-check against the 5.05 table: `0x0061BD90` (5.05) → `0x0061AE20` (13.52).

### 2.2 `sceSblDriverUnmapPages` = **`0x0061B500`**

`free_map_mem` (string at `koff 0x00AE9478`, immediately after
`"ERROR: %s(%d) sceSblDriverUnmapPages %d"` at `0x00AE944F`) contains:

```
0x00627C7A  mov rdi, [rbp-0x120]        ; the map descriptor
0x00627C81  call 0x0061B500             ; <- sceSblDriverUnmapPages
0x00627C86  test eax, eax
0x00627C88  je   ...
0x00627C8C  lea rdi, [rip+...]  "ERROR: %s(%d) sceSblDriverUnmapPages %d"
```

Distance check: MapPages→UnmapPages is `0x6E0` here and `0x6D0` on 5.05
(`0x0061C460 - 0x0061BD90`). The whole pair shifted down together by `~0xF70`,
which is what you would expect for one file being edited, not two.

### 2.3 `kmalloc` = **`0x00009520`** and `kfree` = **`0x000096E0`**

`kmalloc(size, malloc_type*, flags)` — 3 args in `rdi, rsi, edx`.

* 667 sites in `.text` execute `mov edx, 0x102` (`M_WAITOK|M_ZERO`) within
  0x40 bytes before a `call rel32`, and the overwhelming majority resolve to
  `0x00009520`. `0x00009520` is also the second most-called target in the
  whole kernel (1,545 callers).
* Direct read of a call site — `0x00627D15`:
  ```
  lea rsi, [rip+X]      ; malloc_type
  mov edi, 0x18         ; size
  mov edx, 1            ; flags
  call 0x00009520
  ```
  and in the same function, `0x00627CB0`:
  ```
  mov rdi, r14          ; the pointer being released
  lea rsi, [rip+X]      ; malloc_type
  call 0x000096E0
  ```
  That function is `free_map_mem` — a free-list manager, which allocates a
  0x18-byte list node and frees the payload. Alloc/free, in that order.

Cross-check: 5.05 has `kmalloc = 0x0010E250`, `kfree = 0x0010E460`
(`kfree = kmalloc + 0x210`); here `kfree = kmalloc + 0x1C0`. Same ordering,
same magnitude.

### 2.4 `malloc_type` for our allocations = **`0x01AECCB0`**

`struct malloc_type *`, passed as `kmalloc`'s second argument. Recovered from
`sceSblDriverMapPages`'s own body (three `lea rsi, [rip+…]` all resolving to
`koff 0x01AECCB0`), so it is **known-valid**: the kernel already uses it.
It lives in the file-backed part of the second PT_LOAD, so it is present at
runtime.

Using a wrong `malloc_type` pointer is a panic risk under `INVARIANTS`
(`"malloc: bad malloc type"`), which is why this is taken from a real call
rather than from the 5.05 `M_AUTHMGR` value.

Note: `M_AUTHMGR` from 5.05 (`0x01A727E0`) is **not** used — the AuthMgr does
not `kmalloc` at all on 13.52. `sceSblAuthMgrAuthHeader` at `0x00642C90` uses
the four pre-allocated per-context 0x1000 buffers at `koff 0x0269C2C0`
(visible as `add rdi, qword ptr [rip+…]` → `koff 0x0269C2C0`).

---

## 3. Transfer primitives (both disassembled before use)

Nothing in the payload dereferences a user pointer directly.

| koff | signature | evidence |
|---|---|---|
| `0x002BD6A0` | `copyout(kaddr, uaddr, len)` | validates **arg2** as a user address (`add rax,rsi,rdx`; `cmp rax, 0x800000000000`; `ja EFAULT`), `and rsi, 0x7fffffffffff`, `xchg rsi,rdi`, `rep movsq` `[rdi] <- [rsi]`. Also equals libPS4's `K1352_COPYOUT`. |
| `0x002BD790` | `copyin(uaddr, kaddr, len)` | mirror image: validates **arg1** as a user address (`mov rax,rdi; add rax,rdx; cmp rax,0x800000000000`), `and rdi, 0x7fffffffffff`, `xchg rsi,rdi`, `rep movsq` user → kernel. Returns `0` or `0xe` (EFAULT). |
| `0x002BD4E0` | `bzero(dst, len)` | `rep stosq`. |

(`0x002BD5A0` is a plain kernel `memcpy(dst, src, len)`; not used.)

---

## 4. Already-confirmed symbols reused

| symbol | koff | how it was confirmed |
|---|---|---|
| `sceSblServiceMailbox` | `0x00630230` | reached by `_sceSblAuthMgrSmFinalize`'s own `call 0xffffffff82830230` |
| `sceSblAuthMgrModuleId` | `0x0269C0A0` | `mov rdi, qword ptr [rip+0x205c129]` in `SmFinalize` |
| `authmgr_sm_xlock` | `0x0269C0C8` | `lea r12, [rip+…]`, then `_sx_xlock` on it in `SmFinalize` |
| `_sx_xlock` / `_sx_xunlock` | `0x000A3840` / `0x000A3A00` | the lock/unlock pair bracketing the mailbox call |
| `self_ctx_status` | `0x0269C130` | `cmp dword ptr [rip+…], 0` ×4 in `sceSblAuthMgrAuthHeader`; reads `[3,3,3,3]` in the live dump |
| `self_contexts` | `0x0269C140` | `lea r13, [rip+…]` in `AuthHeader`; stride `0x60`, decodes correctly from the dump |
| `_sceSblAuthMgrSmFinalize` | `0x0063FF00` | its whole body was read: `bzero(stack,0x80)`, `payload[0]=5`, `_sx_xlock`, `sceSblServiceMailbox`, `_sx_xunlock`, `kprintf` on error |

### `_sceSblAuthMgrSmFinalize` body — the template for the protocol

```asm
0x0063FF00  push rbp / mov rbp,rsp / push r15,r14,r13,r12,rbx / sub rsp, 0x88
0x0063FF14  lea rax, [rip+...]        ; stack canary -> koff 0x0275CEA0
0x0063FF22  mov rbx, rdi               ; rdi = &self_contexts[ctx]
0x0063FF25  mov esi, 0x80
0x0063FF2A  mov rdi, r15               ; r15 = rbp-0xb0
0x0063FF34  call 0x002BD4E0            ; bzero(payload, 0x80)
0x0063FF39  mov qword [rbp-0xb0], 5    ; *** payload[0] = AUTHMGR_CMD_FINALIZE ***
0x0063FF44  lea r12, [rip+...]         ; koff 0x0269C0C8  authmgr_sm_xlock
0x0063FF5C  mov eax, [rbx+0x1c]        ; ctx->ctx_id
0x0063FF65  mov [rbp-0xa8], eax        ; payload[8] = context_id
0x0063FF6B  call 0x000A3840            ; _sx_xlock(sm_xlock, 0, file, line)
0x0063FF70  mov rdi, [rip+...]         ; koff 0x0269C0A0  module id
0x0063FF77  mov rsi, r15 / mov rdx, r15
0x0063FF7D  call 0x00630230            ; sceSblServiceMailbox(id, pkt, pkt)
0x0063FF8F  call 0x000A3A00            ; _sx_xunlock
```

Two things fall out of this and they matter:

1. `payload[0] = 5`, and the PS5 reference's `authmgr.h` names
   `SBL_FUNC_AUTHMGR_FINALIZE 0x05`. The PS4 and PS5 numbering agree.
2. The packet is sent as **both** query and reply (`rsi == rdx == &payload`),
   exactly like the reference's `sceSblServiceMailbox_locked`.

`AUTHMGR_CMD_VERIFY_HEADER 0x01` / `LOAD_SELF_SEGMENT 0x02` / `LOAD_SELF_BLOCK
0x06` come from the same PS5 table and were cross-checked against the orbital
PS4 `ksdk_sbl.h`, which gives the same numbers.

---

## 5. Packet layouts (0x80 bytes, identical in both references)

```
sbl_authmgr_verify_header_t                        sbl_authmgr_load_self_segment_t
0x00 u32 function = 0x01                           0x00 u32 function = 0x02
0x04 u32 status     (checked == 0)                 0x04 u32 status
0x08 u64 header_addr   (BUS address)               0x08 u64 chunk_table_addr (BUS)
0x10 u32 header_size                              0x10 u32 segment_index
0x14 u32 zero                                      0x14 u32 is_block_table
0x18 u32 zero                                      ---------------------------------
0x1C u32 context_id  (IN ctx, OUT auth ctx)       sbl_authmgr_chunk_table_t
0x20 u64 auth_info_addr (BUS)                      0x00 u64 data_addr  / first_pa
0x28 u32 unk                                       0x08 u64 data_size
0x2C u32 key_id                                    0x10 u64 num_entries
0x30 u8  key[0x10]                                 0x18 u64 reserved
                                                   0x20 u64 entries[0].data_addr
                                                   0x28 u64 entries[0].data_size
```

Field-by-field these agree between `orbital-ref/.../ksdk_sbl.h` and
`ps5-selfdec-ref/include/authmgr.h` — the only naming differences are
`context_id` (PS4) vs `service_id` (PS5) at `+0x30`/`+0x1C`, which are the same
field.

### Why `80010008` is the easiest possible target

```
seg[0] flags=0x0000000006  off=0x0013e0  size=0x10f9c   idx=0  [ENC|SIG]
seg[1] flags=0x0000100006  off=0x0123e0  size=0x02d84   idx=1  [ENC|SIG]
seg[2] flags=0x0000200006  off=0x0153e0  size=0x00510   idx=2  [ENC|SIG]
header_size 0x160, metadata_size 0x280  ->  hdr_len 0x3e0
```

Bits 11 (`BLOCKED`), 16 (`HAS_DIGESTS`) and 17 (`HAS_EXTENTS`) are **clear** on
all three segments. The reference's block loop therefore does nothing; the
whole job is `VERIFY_HEADER`, then one `LOAD_SELF_SEGMENT` per segment with
`is_block_table = 0`, then copy the plaintext back out. No chunk iteration, no
digests, no block table.

---

## 6. What is NOT done, and the one hard constraint

* **`_sceSblAuthMgrSmStart` (`koff 0x0063E470`) is never called.** It took this
  console down twice. It is also unnecessary: the "SM started" byte at
  `koff 0x0269C098` already reads `1` on a booted 13.52 console (verified in
  the 20 MB kernel dump).
* The live dump also shows `self_ctx_status = [3,3,3,3]` (all four free),
  `self_contexts[i].format = 2` (ELF), `ctx_id` populated, and the per-context
  `header` pointers pointing into the `0xffffc187…` SELF arena.

The remaining unknown is whether `sceSblServiceMailbox` will answer with
`self_contexts` free and `sceSblAuthMgrModuleId == 0` in the dump. That is why
the payload is staged: step 6 **reads** the module id and refuses to issue any
SM command while it is 0 (`svcreq=1` in `sd.cfg`), instead of risking a
blocking wait on a mailbox with no destination.

---

## 7. How the offsets were derived (tooling)

* `derive_sbl_missing.py` — SDK calibration, call-graph, the `mov edx,0x102` scan
* `xref_strings_1352.py` — string extraction + deterministic RIP-relative
  operand scanner (231,369 operands decoded) → string→code xrefs
* `pin_mapfns.py`, `pin_mapfns2.py`, `pin_rest.py` — entry pinning and call
  target resolution
* `identify_memfns.py`, `dump_copyin.py` — copyin/copyout/bzero discrimination
* `check_sm_state.py` — reads the live AuthMgr state out of `v11_kmem_img.bin`
* `verify_selfdec2.py` — asserts `0x63E470` is absent from the built payload
  and that every needed constant is present

---

# 8. Run-3 re-derivation: the packet was never the problem

Run 2 (the `ctx_id` hypothesis) still returned EINVAL, so the packet was
re-derived from the kernel's *own* command builders rather than from the
references. Four things came out of that, and the last one is the real defect.

## 8.1 The SM command table, read straight off the wire format

Scanning every function in the SBL region (`0x63C000..0x645000`) for a store of
a small immediate into a stack slot that is then handed to
`sceSblServiceMailbox` produced the complete command set:

| cmd | builder | other callees | identity |
|---|---|---|---|
| `0x01` | **`0x6401F0`** | – | **VERIFY_HEADER** |
| `0x02` | `0x640630` | `sm62fb60`, `sm62fd20`, `sm6442b0` | LOAD_SELF_SEGMENT |
| `0x05` | `0x63FF00` | – | FINALIZE |
| `0x06` | `0x640AA0` | `mappages` | LOAD_SELF_BLOCK |
| `0x16` | `0x63FFF0` | `sm655f20`, `sm655f50` | generic `SmRequest` |
| `0x0B 0x0E 0x10 0x11 0x15 0x17 0x18 0x19 0x401 0x402` | `0x63E9xx..0x6419xx` | – | not AuthMgr-facing |
| `0x100 0x101 0x102 0x103 0x110 0x500` | `0x63D960..0x63F2E0` | `mappages` | SblDriver layer |

Two layout families exist and the distinction is load-bearing:

* **AuthMgr** writes the command as a **`u16` at `+0x00`** and the status is the
  **`u32` at `+0x04`**. `SmFinalize` writes `mov qword [rbp-0xb0], 5`, which is
  byte-identical to a `u16` 5 at `+0x00` with the upper 6 bytes left zero by the
  preceding `bzero` — so `+0x00` is a `u16` field, not a `u64`.
* The `0x401/0x402` builders use a genuinely wider field. They are not ours.

## 8.2 `_sceSblAuthMgrSmVerifyHeader` @ `0x6401F0` — the authoritative packet

```
64020b  mov r14, rdi                        ; rdi = &self_contexts[idx]
640216..64029d  zero [rbp-0x38] .. [rbp-0xb0]     ; 0x80-byte packet
6402a8  lea rax, [rip + ...]                ; koff 0x0269C0B8
6402af  mov ebx, dword ptr [rdi + 0x30]     ; ctx->buf_id  (0..3)
6402b2  mov word ptr [rbp - 0xb0], 1        ; *** packet+0x00 = 1 ***
6402bb  mov ecx, dword ptr [rdi + 8]        ; ctx->total_header_size
6402be  shl ebx, 0xc
6402c1  add rbx, qword ptr [rax]            ; BUS = *(0x0269C0B8) + id*0x1000
6402c4  mov dword ptr [rbp - 0xa0], ecx     ; packet+0x10 = header_size
6402ca  cmp dword ptr [rdi], 1              ; ctx->format == 1 (plain ELF)?
6402cf  mov word ptr [rbp - 0x88], 1        ;   packet+0x28 = is_plain_elf
6402f2  movabs rax, 0x3100000000000001
6402fc  mov qword ptr [rbp - 0x90], rax     ;   packet+0x20 = magic
640305  mov word ptr [rbp - 0x88], 0        ; ... else SELF: is_plain_elf = 0
64030e  mov qword ptr [rbp - 0x90], 0       ;                 packet+0x20 = 0
640332a cmp dword ptr [r14], 2              ; SELF: sub_63D780 + sub_645110
64035f  call sub_645110                     ;   fill packet+0x2A / +0x2C / +0x30
6403a9  mov qword ptr [rbp - 0xa8], rbx     ; *** packet+0x08 = BUS ***
6403c4  lea rdx, [rbp - 0xb0]
6403cb  mov rsi, rdx
6403ce  call sceSblServiceMailbox           ; request == reply
64040a  mov ecx, dword ptr [rbp - 0xac]     ; packet+0x04 = status
640410  cmp ecx, -0x24                      ; -36 is a handled special case
```

**`packet+0x08` is not a free choice.** It is
`*(koff 0x0269C0B8) + ctx->buf_id * 0x1000` — the BUS address of the secure
module's *own* per-slot staging page. And `ctx->buf_id` is the same number the
slot's VA pointer is derived from. The 2018 orbital dumper put an arbitrary
`MapPages`'d buffer there and it worked on 5.05; on 13.52 that is what produces
EINVAL.

The live 20 MB dump confirms the pair, and that they describe one page:

```
koff 0x0269C0B8 (BUF_B / BUS) = 0x000000000a56c000
koff 0x0269C0B0 (BUF_A / VA)  = 0xffffc18715c2c000
koff 0x0269C2C0 (ctx bufbase) = 0xffffc18715c2c000   <- same page
koff 0x0269C0C0 (BUF_C / BUS) = 0x000000000a72c000
```

So the correct recipe is: write the SELF header's first `0x1000` bytes to
**VA `0xffffc18715c2c000 + idx*0x1000`** and pass **BUS `0xa56c000 + idx*0x1000`**.

## 8.3 `sceSblServiceMailbox` is a software queue, not a doorbell

`0x630230` builds `{u64 9, u64 msgid, u64 to_ret, u32 0, u64 module_id}` — a
`0x28` header — with the `0x80` packet copied in at `+0x28`, and hands it to
`_sceSblServiceRequest` (`0x631630`). That copies it to `*0x2845168 + 0x1000`
and rings `sub_61C3C0`. The two statuses are **different fields**:

* `header+0x04` (`shared+0x1004`) = **transport** status, and it is what
  `sceSblServiceMailbox` returns;
* `packet+0x04` (`shared+0x102C`) = **secure module** status.

Run 2 returned `r = 0` (transport fine) with `packet+0x04 = 0xffffffea`
(module: EINVAL). A transport failure would have logged
`ERROR: sceSblServiceMailbox(0xf1) _sceSblServiceRequest %d` and returned the
value instead. The AuthMgr handler is alive and answering; only the request is
wrong. The error-path strings are at koff `0xAEA62F` / `0xAEA646`.

## 8.4 The zero module id is a red herring, and the slot states are 3

`sceSblAuthMgrModuleId` (`0x0269C0A0`) really does read `0` on a booted console,
but since the transport answers, id 0 resolves. Also, per `SmStart`
(`0x63E470`), the "started" byte `0x0269C098` is written **only** on success of
`sub_6300E0` — so flag = 1 already proves the start succeeded, and the handle
being 0 is not evidence of a missing transport. `SmStart` is still never called.

`self_ctx_status` (`0x0269C130`, `u32[4]`) semantics, from `sceSblAuthMgrLoad`
(`0x6434D0`):

```
643593  mov ecx, dword ptr [rdx + rax*4]   ; rdx = 0x0269C130, rax = ctx idx
643596  inc ecx
643598  cmp ecx, 3
64359b  ja  error                          ; so the stored value must be <= 2
643627  mov dword ptr [rdx + rax*4], ecx   ; ... and is then incremented
```

0 is the pristine state, 3 is exhausted, and the live dump has **all four = 3**.
`sceSblAuthMgrAuthHeader` only ever selects a slot whose state is `0` and
returns EBUSY if none is — so it cannot authorise anything in that state, while
the secure module itself only ever sees the `0x80` packet. `sd.cfg` therefore
gained `ctxidx=` to pin the slot without a rebuild.

## 8.5 Run-3 payload

Step 7 is now a 5-way matrix that stops at the first accepted spelling and
reports every attempt's module status plus the auth ctx id each one returned:

```
  A0  header in the SM's staging page, +0x1C = 0,   +0x20 = 0
  A1  header in the SM's staging page, +0x1C = 0,   +0x20 = ai_bus
  A2  header in the SM's staging page, +0x1C = idx, +0x20 = 0
  A3  header in OUR mapped buffer,    +0x1C = idx, +0x20 = ai_bus   (orbital)
  A4  header in OUR mapped buffer,    +0x1C = 0,   +0x20 = 0
```

Each attempt re-sets the slot fields the kernel sets, `SmFinalize`s the slot
first, then sends. Report lines `st=` and `cid=` are the per-attempt module
status and returned ctx id; `win=` is the winning index or `0xff`.

One open question this run should settle: whether the module additionally wants
the SELF-specific fields at `+0x2A/+0x2C/+0x30` that `sub_63D780` /
`sub_645110` supply, which only exist if the slot's header pointer is populated
the way `sceSblAuthMgrAuthHeader` populates it.

---

# 9. Run-3 result and the two real defects

All five spellings in the §8.5 matrix returned `0xffffffea`, including the
orbital reference verbatim (A3). `cid=` was `0` for every attempt, i.e. the
module never wrote an auth context id — so it was rejecting before that point
rather than objecting to the value we sent at `+0x1C`. The matrix therefore
ruled out the packet fields entirely and pointed somewhere else. Two things
were wrong, neither of them in the packet.

## 9.1 `_sceSblAuthMgrSmVerifyHeader` is live, reached by tail call

A `call rel32`-only scan reports **zero** references to `0x6401F0` anywhere in
the image, which reads as dead code. It is not:

```asm
0x63D100  push rbp
0x63D101  mov  rbp, rsp
0x63D106  mov  rbx, rdi
0x63D109  call 0xffffffff8283e470      ; _sceSblAuthMgrSmStart
0x63D10E  mov  rdi, rbx
0x63D117  jmp  0xffffffff828401f0      ; **_sceSblAuthMgrSmVerifyHeader**
```

`0x63D100(ctx)` is exactly `SmStart(); return verify_header(ctx);` — and
`sceSblAuthMgrAuthHeader` calls `0x63D100` on its success path (`0x6431A6`).
So the chain on 13.52 is:

```
sceSblAuthMgrAuthHeader(ctx, rd)  ->  parse header, set ctx->0x38 / 0x08 / 0x30
                                  ->  sub_63D100(ctx)
                                        SmStart()        (no-op, byte already 1)
                                        verify_header()  -> cmd 1 to the module
```

Lesson worth keeping: **scan for `E9` tail jumps as well as `E8` calls.**
`find_callers.py` and `find_refs.py` only matched `E8` and produced a false
negative that cost a whole investigation round.

## 9.2 `ctx->0x38` is a POINTER, not a BUS address

This is the actual defect. `self_context_t` (which the orbital `ksdk_sbl.h`
declares and the live dump confirms field-for-field):

```
0x00 u32 format                 0x04 u32 elf_auth_type
0x08 u32 total_header_size      0x0C u32 unk
0x10 u64 segment                0x18 u32 unk
0x1C u32 ctx_id                 0x20 u64 svc_id
0x28 u64 unk                    0x30 u32 buf_id
0x34 u32 unk                    0x38 u64 header      <- POINTER
0x40     mtx
```

`sub_63D780(ctx, void **out)` dereferences it as a pointer:

```asm
63D784  mov  r8,  qword ptr [rdi + 0x38]      ; r8 = ctx->header
63D792  movzx r9d, word ptr [r8 + 0x18]       ; num_entries
63D797  movzx ecx, word ptr [r8 + 0xc]        ; header_size
63D7A8  movzx eax, word ptr [r8 + r9 + 0x58]  ; digest/extent table entry
63D7D3  mov  dl,  byte ptr [rdi + rcx + 0x40]
63D7DD  jne  0x63d7e9                         ; -> returns 0xfffffffe, *out UNSET
63D7E4  mov  qword ptr [rsi], rax
```

And `verify_header` then does:

```asm
64033A  call sub_63D780
640364  test eax, eax
640366  jne  0xffffffff82840396              ; *** FAILURE -> SKIP THE WHOLE BLOCK ***
640368  lea  rsi, [rbp - 0xc0]
640374  mov  rdi, r15                         ; packet+0x30
640377  call memcpy                           ; 0x10 bytes
640389  mov  dword ptr [rbp - 0x84], eax      ; packet+0x2C
64038F  mov  word  ptr [rbp - 0x86], cx       ; packet+0x2A
```

Every previous run stored a **BUS address** in `ctx->0x38` (the correct value
for `packet+0x08`, which is a different field entirely). `sub_63D780` therefore
failed, `verify_header` silently dropped `packet+0x2A/+0x2C/+0x30`, and the
module rejected the result. Nothing in the packet that we were varying could
ever have fixed that — which is precisely why all five spellings gave the same
answer.

The packet is assembled one field at a time, so no single earlier probe could
have separated the three cases: BUS field right / pointer field wrong, and vice
versa.

## 9.3 `verify_header`'s return contract (koff `0x6401F0`)

```asm
640506  mov  ecx, dword ptr [rbp - 0xac]      ; packet+0x04 = module status
64050C  je   0xffffffff8284053a
64052A  mov  ebx, dword ptr [rbp - 0xac]      ; non-zero -> return it directly
64053A  movzx ecx, word ptr [rbp - 0xb0]      ; packet+0x00 must echo 1
640541  cmp  ecx, 1
640544  jne  0xffffffff828405e4               ; else return 0xffffffd8 (-40)
64054A  mov  eax, dword ptr [rbp - 0x94]      ; packet+0x1C
640552  mov  dword ptr [r14 + 0x1c], eax      ; *** ctx->ctx_id = packet+0x1C ***
640556  jmp  0xffffffff82840603               ; return 0
```

Three things this settles:

1. **The return value IS the module's status.** `-22` from this call means the
   module said EINVAL, `-40` means the reply's command echo was wrong, `0` means
   accepted. A single `call` here is therefore as diagnostic as reading the
   packet ourselves, and it also exercises the real code path.
2. **`packet+0x1C` is a pure OUTPUT.** The kernel never writes it (it is
   `bzero`'d and read back), so the correct input is `0` — not the slot index
   the 2018 reference used, and certainly not a value read out of `ctx+0x1C`.
   This retires the run-2 change for good.
3. **The slot's `ctx_id` is only ever populated from that reply.** Which means
   on a fresh slot it legitimately starts at 0, exactly as the kernel's own
   `bzero(ctx, 0x60)` implies.

Two adjacent facts worth recording: `packet+0x20` is `0` for a SELF and
`0x3100000000000001 | {0,1,0x1000,0x1001,0x1100,0x1101}` for a plain ELF via a
relative jump table at `0x64054A`; and header magic `0x1d3d154f` is checked by
`sub_63D7F0` (called from `AuthHeader` at `0x642FDB`), not by `verify_header`.

## 9.4 Run-4 payload

Step 7 no longer hand-assembles anything. It:

1. copies the first `0x1000` bytes of `target.self` to
   `*(0x0269C2C0) + idx*0x1000` (the module's staging page, by kernel VA);
2. populates the slot as `AuthHeader` does — `format = 2`,
   `total_header_size`, `ctx_id = 0`, `svc_id`, `buf_id = idx`, and
   **`header = ` that page's kernel VA**;
3. probes `sub_63D780` first and reports its return plus the resolved digest
   pointer, so a silent skip of the SELF block becomes visible;
4. `SmFinalize`s the slot, then calls `_sceSblAuthMgrSmVerifyHeader`
   (`0x6401F0`) and reports its return value as the module's verdict;
5. on success adopts `ctx->0x1C` as the auth context id for step 8.

`SmStart` is still never called, and the payload is asserted to contain no
reference to `0x63E470`.

Now the new report line is:

```
hdrptr=<VA>  verify=<module status>  ctxid_out=<auth ctx id>  ctx20=<svc>
bus=<BUS passed>  bufB=  cbb=  smflag=
digest=<sub_63D780 rc>  dptr=<resolved ptr>  idx=  copyin=
ownbus=<our own mapped buffer, for reference>
```

`verify=0` means the SELF header was accepted and step 8 can follow.
`digest=fffffffe` would mean the header's digest/extent tables do not line up,
i.e. the staged page does not hold the header the module expects.

---

# 10. Run-4 result: EINVAL is a missing KEY, not a malformed packet

Step 7 now calls the kernel's own `_sceSblAuthMgrSmVerifyHeader`, and the
probe line names the failure exactly:

```
hdrptr=ffffb6d605e6c000  verify=ffffffffffffffea  ctxid_out=0  ctx20=0
bus=5e6c000  bufB=5e6c000  cbb=ffffb6d605e6c000  smflag=1
digest=fffffffffffffffe  dptr=0  idx=0  copyin=0
ownbus=2e374000
```

`digest = 0xfffffffe` is `sub_63D780` failing. And `verify_header` reacts to
that failure by **silently dropping `packet+0x2A`, `+0x2C` and `+0x30`**:

```asm
64033A  call sub_63D780
640364  test eax, eax
640366  jne  0xffffffff82840396     ; *** SKIP ***
640377  call memcpy                 ; packet+0x30, 0x10 bytes
640389  mov  dword ptr [rbp - 0x84], eax   ; packet+0x2C
64038F  mov  word  ptr [rbp - 0x86], cx    ; packet+0x2A
```

Those three fields are **`key`, `key_id` and a u16** — the orbital
`ksdk_sbl.h` struct spells the tail out as `key_id` at `0x2C` and
`key[0x10]` at `0x30`, and `sub_645110` is what produces them. So the module
was never rejecting our packet shape; it was rejecting a packet **with no key
in it**. Every earlier "wrong spelling" conclusion was downstream of that.

## 10.1 `sub_645110` is a key lookup, and the keys are in the kernel

```asm
64516D  mov  rbx, qword ptr [rip + 0x205718C]   ; koff 0x0269C300 = list head
6451AC  memcmp(rbp-0x98, rbx, 0x20)             ; digest == node->digest ?
6451D3  lea  rsi, [rbx + 0x20]                  ; match: node->value
6451DF  call memcpy                             ; -> packet+0x30 (the KEY)
6451E4  mov  eax, dword ptr [rbx + 0x40]        ; -> packet+0x2C (key_id)
6451FA  mov  eax, dword ptr [rbx + 0x44]        ; -> packet+0x2A
6451A0  add  rbx, 0x48
6451A4  mov  rbx, qword ptr [rbx]               ; node->next
```

So the console holds a singly-linked list of

```
node+0x00  0x20  digest (the lookup key)
node+0x20  0x20  value   (first 0x10 == the SELF key)
node+0x40  u32   key_id
node+0x44  u32   (-> packet+0x2A)
node+0x48  u64   next
```

**This is worth more than the SM round trip it was blocking.** It is the
digest->key table, in kernel memory, at a fixed koff, and reading it is
read-only. If the values are usable key material, matching the digests against
the per-segment digests already present in a SELF header gives that SELF's key
directly — offline, with no secure-module interaction at all. Step 7 now dumps
the whole list to `sd_keys.txt` (hex, one node per line, 32 nodes max, with an
obvious-pointer guard on each link) before it attempts anything.

## 10.2 `ctx->0x38` is the raw header — but `sub_63D780` still refuses it

`AuthHeader` copies the header into `ctx->0x38` itself:

```asm
6430D5  mov  rax, qword ptr [rbp - 0x58]   ; &ctx->0x30
6430DC  mov  rdi, qword ptr [rax + 8]      ; ctx->0x38 === the staging page
6430E0  call memcpy                        ; memcpy(ctx->0x38, header, hdr+meta)
```

so `ctx->0x38` genuinely does hold the raw header, `r8` really is the header
buffer, and yet the arithmetic in `sub_63D780` cannot be satisfied by it.
Simulating it (`sim_all.py`, `sim_all2.py`) over **all nine** SELFs on hand —
including `80010002` and `orbis_swu`, which this console demonstrably loads —
it returns `-2` for every one of them. Re-reading the size field as
`header_size + metadata_size` (which is what `AuthHeader` stores as
`ctx->total_header_size` and hands to the module as `packet+0x10`) makes the
first check pass for all nine, but the second still fails, so the structure it
expects is not the on-disk header either way.

That is an open question, and it is now a **secondary** one: resolving the key
is the thing that unblocks `verify_header`, and the key dump needs none of it.
The brute-force base search (`brute_63d780.py`) is not conclusive — too many
garbage bases satisfy both checks by chance — so it is not evidence of anything
and is recorded only so it is not repeated.
