# Stage 2 findings — where the SELF keys are, and are not

**Date:** 2026-09-20 · Console: PS4, 13.52, GoldHEN · kbase `0xffffffff85680000` (ASLR-slid)
**Goal:** decrypt `dec/80010002_kernel_14.00.self` (10,867,186 B, still encrypted)
**Question this document answers:** can the 14.00 kernel be decrypted by dumping the console's kernel memory?

**Answer: no.** Below is the evidence, in the order it was obtained.

---

## 1. The method that works, and the one that killed the console twice

`get_memory_dump()` in libPS4 is a thin `copyout` wrapper:

```c
int ret = copyout((uint64_t *)kaddr, (uint64_t *)uaddr, size);
if (ret == -1) memset(uaddr, 0, size);
return ret;
```

It returns 0 on success, non-zero on failure, and does not panic — which is what
makes a linear walk possible at all.

| Attempt | Chunk size | Window | Result |
|---|---|---|---|
| v7 | **0x20000 (128 KiB)** | kernel `.data` | **console powered off** |
| v9 | 8 B | 9 probe addresses | all `r=0` |
| v10 ladder | 8 → 4096 B | same address, growing | all `r=0` up to 4096 |
| v10 dump | 0x1000 (4 KiB) | 128 KiB | clean, `fails=0` |
| v10 dump | 0x1000 | 19.1 MB kernel `.data`/`.bss` | clean, 4885 chunks, `fails=0` |
| v12 dump | 0x1000 | 8 MB arena | clean, 2048 chunks, `fails=0` |

**Root cause of the two failures: copyout size, not address.** v7's
`kmem_img.bin` was 0 bytes with the file present, and `kmem_img.txt` was never
created — so the console died inside the *first* 128 KiB read, before the loop's
first write. v9 then read all nine addresses successfully at 8 bytes, and the
v10 ladder read the *same* address as v7 at 4096 bytes with `r=0`.

Two false leads were eliminated on the way:

- **Unmapped address** — no. `1352k.elf` has exactly two PT_LOADs
  (`0x0..0xcfe758` R-X, `0x1520000..0x2834af0` RW-, gap `0xcfe758..0x1520000`),
  and v7's first 8 MB sat wholly inside the mapped RW segment.
- **kexec storm** — no. `kexec` is `SYSCALL(kexec, 11)`: one kernel entry on the
  calling thread, no thread spawned, no leak.

## 2. Hardware confirmation of the offset derivation

The v9 probe read nine addresses in PT_LOAD 1 — the first time any address
outside `.text` was read on this hardware:

```
P0 1520000 r=0 v=205359534942524f   LE bytes 4f 52 42 49 53 53 03 20 = "ORBISS"
P1 1521000 r=0 v=ffffffff85df1204   kbase + 0x771204
P2 1b265e8 r=0 v=0
P3 1b266e8 r=0 v=0
P4 2000000 r=0 v=0
P5 269c000 r=0 v=ffffc18715c02c00
P6 269c0a0 r=0 v=0
P7 269c140 r=0 v=2
P8 2834ae8 r=0 v=4
```

The v10 window then resolved the AuthMgr context table exactly as
`offsets_1352.h` predicts:

```
ctx[0] @0x269c140  state=2 idx=0x0 buffer=0xffffc18715a6c000
ctx[1] @0x269c1a0  state=2 idx=0x1 buffer=0xffffc18715a6d000
ctx[2] @0x269c200  state=2 idx=0x2 buffer=0xffffc18715a6e000
ctx[3] @0x269c260  state=2 idx=0x3 buffer=0xffffc18715a6f000
```

`CTX_OFF_STATE=0x00` → 2, `CTX_OFF_INDEX=0x30` → array index, `CTX_OFF_BUFFER=0x38`
→ pointers exactly `0x1000` apart. Every claim in the offset table holds.

**And one fact that explains the v6 softlock:**

```
SM_FLAG          @0x269c098 = 0x1   <- the secure module is ALREADY STARTED
AUTHMGR_HANDLE   @0x269c0a0 = 0x0
```

v6's first action was `_sceSblAuthMgrSmStart` (koff `0x63E470`), on the premise
that the SM transport was down and needed starting. It was not down. That call
took the module-loader path for a module already running, blocked, and held a
lock the notification/logging path also needs — which is why the console
soft-locked with *zero* log output, our own prints included.

## 3. The SELF keys are not in kernel memory

Two searches, both negative:

| Dump | Size | Window | Exact key-bank SHA-256 hits | Terminator-shape matches |
|---|---|---|---|---|
| kernel image | 20,007,664 B | koff `0x1520000..0x2834af0` | **0** | **0** |
| arena | 8,388,608 B | `0xffffc18716000000..+8MB` | **0** | **0** |

The kernel-image search also brute-forced all 20,007,664 sixteen-byte windows
against Al-Azif's three `80010008.py` key-bank signatures in 38.4 s. (An earlier
offline scan of all five local decrypted kernel ELFs — including `.text` — was
also 0 hits, so the text segment is covered too.)

## 4. Why — and this is the structural finding

The arena window contains a real SELF image, and it is **still encrypted**:

```
0xffffc187160e4200  4f 15 3d 1d  SELF magic
  file_size  98,672            <- exactly 80010001 (Secure Kernel)
  [0] props=0x000007  off=0x12f0  filesz=0x54     enc=1 comp=0
  [1] props=0x100007  off=0x22f0  filesz=0x15e80  enc=1 comp=0
  segment[0] body first16: 97 85 1f 2f 1a 2b 96 15 ...
```

Compare with the recorded parse of `/dev/sflash0s1.cryptx3`:
`80010001 SecureKernel: seg[0] props=0x000007 enc=1 comp=0 -> 97 85 1f 2f …`

Byte-for-byte identical. The console keeps module images **encrypted** in kernel
memory; it does not retain a decrypted copy.

Following the pointer graph from the one module descriptor that exists
(`0xffffc18716072780`, carrying name `8001000B` and size `58,276` — matching the
SLB2 directory exactly) leads to:

```
0xffffc187160d8d00  "obi.sflash0s1.crypt"    <- /dev/sflash0s1.crypt
0xffffffff870eddc0  kernel .text (kbase + 0xa6ddc0)
```

i.e. the SBL's structures describe **reading encrypted storage**, not holding
decrypted modules.

### Conclusion

The `sceSblAuthMgr*` code in the kernel's `.text` is the kernel-side
**message-passing driver**. `80010008` (AuthMgr) itself — the module whose data
contains the SELF key banks — runs on the **secure processor**, behind the SM
mailbox. Its plaintext and its keys never appear in the x86 kernel's address
space.

This **falsifies Stage 2 option (b)** in `14.00-KERNEL-ROUTE.md`, which stated the
AuthMgr "is running, in plaintext" in kernel memory and could be dumped. It is
not, and it cannot be. 27 MB of kernel memory across both regions, zero hits, plus
direct evidence that resident module images are encrypted.

## 5. What remains

The 14.00 kernel still is not decrypted, and exactly one artifact is still
missing: a decrypted `80010008` for 13.52.

Two routes survive:

**(a) Use the console's own AuthMgr as an oracle.** Drive the SM through
`sceSblAuthMgrSmRequest` (koff `0x63FFF0`, signature `(ctx, cmd, _, auth_info_in,
auth_info_out)` per the offset derivation) with one of the four confirmed active
contexts, to make the secure module decrypt `80010008.self`'s own segments.
The SM is already up (`SM_FLAG=1`) and the contexts are live, so the request path
should be serviced rather than block. **Critically: do not call
`_sceSblAuthMgrSmStart`** — that is the call that killed the console.
This is the documented route 2(a) and is now the only one that needs no external
key material. It is also the largest remaining build.

**(b) Obtain the system-modules keyset (revision 1.4).** Decrypt `80010008.self`
offline, run `80010008.py`, get the SELF keys, decrypt the 14.00 kernel offline.
Not available publicly — searched, no result at 13.50/13.52. Note that
[ps4-cfw-toolkit](https://github.com/Al-Azif/ps4-cfw-toolkit) covers only
EAP KBL / EAP Kernel / EMC IPL / Syscon and explicitly states for SELF files:
*"Private keys are NOT on the console"*. So this route requires deriving the
keyset through the EAP/EMC chain, not reading it out of kernel memory.

**Route (b) is also why the whole exercise is hard.** The reason someone can turn
new-firmware offsets around in days is a toolchain that drives the on-console
AuthMgr — route (a).

## 6. Reusable outcome

Regardless of which route is taken next, this stands on its own:

- A **safe, proven kernel-memory dump method** for this console: 4 KiB chunks via
  `get_memory_dump` only, stopping at the first failed read, with a per-chunk
  status file so a failure is localizable. `kmemdump/` in this workspace.
- `start` / `end` / `chunk` / `abs` are config-driven from `/mnt/usb0/kmem.cfg`,
  so new windows need no rebuild.
- The AuthMgr context table, the SM handle, `SM_FLAG`, and the offset table's
  `CTX_OFF_STATE` / `CTX_OFF_INDEX` / `CTX_OFF_BUFFER` semantics are now
  **hardware-confirmed**, not inferred.

---

# 7. THE ANSWER — authoritative route, from psdevwiki

Source: [PS4 SELF File Format — psdevwiki](https://www.psdevwiki.com/ps4/SELF_File_Format),
section "SELF Decrypter on PS4":

> *"PS4 SELF Decrypter on PS4 by AlexAltea. **As PS4 SELF decryption keys are not
> publicly known, to decrypt SELFs, one can use his PS4 as a blackbox.** There are
> some conditions: the SELF must have valid signatures, it must have a **required
> FW version lower than the FW version of the PS4 being used**, and for System
> SELFs the **SELF key_revision must be according to the PS4 FW version**."*

Three consequences, and they settle every open question:

**7.1 The keyset route is dead, permanently.** "PS4 SELF decryption keys are not
publicly known." The wiki itself redacts key material. There is no download
shortcut, and there never will be. Stop looking.

**7.2 The console-as-blackbox is THE method.** One method, published, by
AlexAltea. Not a hack — the documented way.

**7.3 The 14.00 kernel SELF cannot be decrypted on a 13.52 console.** The required
FW of the 14.00 kernel is 14.00, which is *not* lower than 13.52. The blackbox
will refuse. Any plan that points the decrypter at `80010002_kernel_14.00.self`
is dead on arrival.

## 7.4 The route that does work

The FW check is a property of the **blackbox**, not of the cipher. Offline
decryption has no version check. So: get the keys from a module the console
*will* decrypt, then decrypt the 14.00 kernel on the PC.

1. **Blackbox-decrypt `dec/1352/80010008.self`** (AuthMgr, 88,304 B).
   Its required FW is 13.52 and its key_revision is 1.4 — both match the console.
2. **`80010008.py`** on the result → SELF key banks (AES key+IV pairs).
3. **Decrypt `dec/80010002_kernel_14.00.self` offline** with those keys. No console,
   no FW check. Per the wiki's keyset table, `1 | 4 | 13.50-??.??` is still open —
   **14.00 is very likely still key_revision 1.4, the same as 13.52.** That is the
   single assumption the whole plan rests on.
4. **Verify** against the digest in the SELF's Program Identification Header
   (wiki: "Digest — SHA-256 of the decrypted elf").

**Primary risk on step 1:** the wiki says "lower than", and 80010008.self's
required FW is 13.52 — *equal* to the console, not lower. If the check is strict
`<` this fails. Fallback: use the **13.50** build of 80010008 (also key_revision
1.4, required FW 13.50 < 13.52 → passes cleanly). Do not reach for anything
older — 13.04 is key_revision 1.3 and would give the wrong keys.

## 7.5 Format facts that make offline decryption tractable

Also from the same page, and all consistent with what we read off the real files:

- **Number of segments (SELF hdr +0x18):** "1 Kernel, 2 SL and Secure Modules" —
  matches `80010001.self` reading 2 entries, and the kernel reading 1.
- **Segment flags:** `SF_ENCR=0x2 SF_SIGN=0x4 SF_DFLG=0x8 (deflated) SF_BFLG=0x800 (block)`.
  - Secure modules: "only signed and encrypted, not compressed, blocked or ordered" → simple AES-CBC.
  - Kernel 80010002: "signed, encrypted, compressed, ordered, not blocked" → props `0x40F`, exactly what the 13.52 kernel SELF reads.
- **Segment Certification:** AES key at +0x00, AES IV at +0x10, SHA256-HMAC at
  +0x20, HMAC key at +0x40, RSA signature at +0xB0. (Deduced from a leaked
  decrypted 6.00b1 kernel.)
- **Program Identification Header** carries the "System Software Version"
  (requested minimum — the field the blackbox checks) and the plaintext digest.

## 7.6 So the work left is exactly one thing

**Build the blackbox SELF decrypter payload and point it at `80010008.self`.**

Everything needed is now confirmed, not guessed:

| Piece | Status |
|---|---|
| `sceSblAuthMgrSmRequest` koff | `0x63FFF0`, signature derived and disassembly-backed |
| AuthMgr context table | **hardware-confirmed** — 4 contexts, `state=2`, `idx=0..3`, buffers `0x1000` apart |
| SM transport | **up** (`SM_FLAG @0x269c098 = 1`) — the shell uses it continuously, so the request path is serviced, not blocked |
| Command IDs | `VERIFY_HEADER 0x1`, `LOAD_SELF_SEGMENT 0x2`, `LOAD_SELF_BLOCK 0x3` |
| Safe way to collect plaintext | the proven 4 KiB `get_memory_dump` method in `kmemdump/` |
| **Never call** | `_sceSblAuthMgrSmStart` (koff `0x63E470`) — already cost two reboots |

The one thing still genuinely missing is the **exact argument layout and call
sequence** of the three commands. That must be taken from a reference
implementation (AlexAltea's `self_decrypter.c` or equivalent) — **not invented**.
Inventing it is precisely what the v6 `_sceSblAuthMgrSmStart` mistake was.
