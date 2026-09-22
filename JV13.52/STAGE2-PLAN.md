# STAGE 2 — Plan to get the SELF keys (and why it's not one build)

**Date:** 2026-09-20 · follows `STAGE1-RESULTS.md`

> ### ⚠️ REVISION (2026-09-20, same day) — §4 replaced
> Audited the claim "we already have the 11 offsets from the GoldHEN jailbreak".
> **Verdict: the offsets are not in any offset table we hold, but we do not need a kernel dump to get them.**
> - `sdk/fw_defines.h` (the full Al-Azif `ps4-payload-sdk` table, 1244 lines) carries **17** `K1352_*` offsets.
>   Grepped for all 11 required names: **0 of 11 are present.** Those 17 are *loader* symbols
>   (`MMAP_SELF_*`, `COPYOUT`, `NPDRM_*`…); the 11 are *auth-manager / SBL-mailbox* symbols. Different subsystem.
> - `offset_datacave_1/2` need **no** derivation (README: "any two 0x4000 byte ranges that seem unused").
> - The other 9 are each defined as a **fixed delta from a pointer to a known kernel string**. The README's stated
>   design goal is portability "**even without kernel .text dump**". We already execute kernel payloads on this
>   console, so we hold kernel arbitrary read → hunt the strings **live** and read the deltas off a log.
> - Net: old **2a (dump kernel) + 2b (derive statically) are replaced** by a single cheap scanner run. 5 steps → 4.

---

## 1. What is proven vs not

| | status |
|---|---|
| **Method:** console-as-decryptor for a *newer* retail PUP on 13.52 | ✅ **PROVEN** — ran end-to-end today. Repeatable recipe. |
| Build pipeline (ps4-payload-sdk + Docker, custom payload) | ✅ **PROVEN** — produced and ran `pup-decrypt-1352.bin` |
| The PUP is firmware 14.00 | ✅ **PROVEN** — decoder validated against the console's own 13.52 kernel |
| 14.00 kernel SELF extracted | ✅ **DONE** — `dec/80010002_kernel_14.00.self` |
| **SELF-layer decryption (kernel → plaintext ELF)** | ❌ **NOT PROVEN** — different mechanism, zero evidence so far |

Stage 1 tells us nothing about Stage 2. Different crypto layer, different code path.

---

## 2. The blueprint exists — for PS5

**`Cryptogenic/PS5-SELF-Decrypter`** (SpecterDev, unlicense):

> "A payload that uses **kernel arbitrary read/write** to decrypt Signed ELFs (SELFs) from the filesystem and dump the plaintext ELFs to USB drive."

How it works: get the **auth manager handle**, then drive the Sce/Sbl **kernel mailbox** (`SblDrvSendSx`) to make the kernel decrypt each SELF, block by block, and write the plaintext out. Its own log shows the exact target class of file:

```
[+] got auth manager: 4
[+] decrypting /system_ex/common_ex/lib/libSceJsc.sprx...
  [?] decrypting segment=1, block=1/593
```

Portable pieces: `include/authmgr.h`, `include/sbl.h`, `include/self.h`, `include/elf.h`, and `source/authmgr.c` + `source/sbl.c` + `source/main.c` (26 KB).

**Cost:** it needs **11 kernel offsets**:
`offset_authmgr_handle, offset_sbl_mb_mtx, offset_mailbox_base, offset_sbl_sxlock, offset_mailbox_flags, offset_mailbox_meta, offset_dmpml4i, offset_dmpdpi, offset_pml4pml4i, offset_datacave_1, offset_datacave_2`

Its README even documents how to find them by **string reference**, e.g.:
- `offset_authmgr_handle` = +0x30 from the pointer to the `"sdt"` string
- `offset_sbl_mb_mtx` = −0x20 from the pointer to `"SblDrvSendSx"`
- `offset_mailbox_flags` = −0x8 from the pointer to `"req mtx"`
- `offset_mailbox_meta` = −0x18 from the pointer to `"req msg cv"`
- `offset_dmpml4i` = −0x8 from the pointer to `"invlgn"`
- `offset_pml4pml4i` = −0x1C from the pointer to `"pmap"`

⚠️ **There is no public PS4 port.** The ps4-payload-sdk (checked) carries only payload-dev offsets (`XFAST_SYSCALL`, `PRISON_0`, `COPYOUT`, `MMAP_SELF_*`, `NPDRM_*`) — **no auth/SBL/mailbox offsets at all**. We must obtain all 11 ourselves — but per §0/§4 that is a **live string hunt**, not a static derivation from a kernel dump.

---

## 3. What we already hold (Stage 2 inputs)

| artifact | where | note |
|---|---|---|
| 13.52 modules (matching this console) | `dec/1352/*.self` | the **safe test target** — required FW 13.52 ≤ 13.52, so the console *should* decrypt them |
| 14.00 modules (from the PUP) | `dec/unpacked1/secure_modules.bin` | includes the 14.00 AuthMgr |
| 14.00 kernel SELF | `dec/80010002_kernel_14.00.self` | the actual prize |
| console's full coreos container | `probe/coreos_full.bin` | 13,369,344 B, SLB2, 7 modules |

### 13.52 vs 14.00 module comparison

```
module      role                      13.52       14.00       verdict
80010001    Secure Kernel             98,672      98,676      differs
80010002    KERNEL                    10,866,322  10,867,186  differs
80010006    sec module                41,920      41,920      differs
80010008    AuthMgr (SELF keys!)      88,304      88,304      differs
80010009 / 8001000A / 8001000B        17,348 / 25,524 / 58,276   same sizes, differ
```

**Honest read:** the AuthMgr is the *same size* in both, and so are four other modules — but **every module differs byte-for-byte**. That is **inconclusive**, not bad news: a SELF's ciphertext depends on its per-file cert block and its `fw_version` (13.52 vs 14.00), so identical code can produce different bytes. It neither proves nor disproves a keyset change.

The separate signal — Secure Loader revision nonce (`60cf8821…` on the console vs `7ae1c843…` in the PUP) — is likewise not apples-to-apples (per-console vs 7 generic variants). **The keyset question stays open until we actually try the keys.**

---

## 4. The plan (4 sub-steps — REVISED, see §0 revision note)

```
2a.  OFFSET SCANNER payload for 13.52              -> the 9 string-anchored offsets, read off the log
2b.  port the SELF decrypter to PS4 13.52          -> ps4-payload-sdk + authmgr.c/sbl.c + scanned offsets
2c.  run it on the 13.52 AuthMgr (80010008)        -> guaranteed-decryptable target
         -> then 80010008.py  -> SELF key banks
2d.  decrypt the 14.00 kernel SELF offline         -> *** the goal ***
```

**Why the old 2a/2b are gone:** no decrypted 13.52 kernel image is needed to obtain the offsets. The 9 real
offsets are each a fixed delta from a pointer to a known string, and kernel arbitrary read lets us find those
strings **live**. Only 9 need finding; `datacave_1/2` are free-choice scratch ranges.

**Fallback if an anchor string is missing on PS4** (13.52 is PS5's ancestor, not identical): either the original
2a/2b route (dump the kernel, derive statically) or orbital's PS4-native symbol set —
`sceSblServiceMailbox_locked`, `sceSblAuthMgrModuleId`, `self_ctx_status`, `self_contexts`,
`_sceSblAuthMgrSmFinalize`, `sceSblDriverMapPages`.

Feasibility of 2a: the SDK already has the kernel-payload mechanism (`kexec` + `build_kpayload`) **and** the 13.52 offsets (`K1352_*`, 17 of them), plus `get_memory_dump`-style helpers that its own comments say are used by "Module Dumper, App Dumper, and FTP". So this is a known-pattern build with the proven toolchain.

**Risk profile for 2c/2d:** kernel-level code that talks to the secure mailbox. Expect panics; the PS5 README is explicit that "the console may panic in the midst of dumping files, this is fine, restart the console and run again". On PS4 the console is still on 13.52 and the JB is RAM-only, so a panic costs a reboot and a re-jailbreak, nothing more.

**Safety:** still never install 14.00. No payload so far has written to flash, and none of the planned ones need to.

---

## 5. What to say go on

Build **2a** now (kernel dumper for 13.52). It's the gate for everything else, it's a known pattern with the toolchain already proven on your console, and its output is useful even if Stage 2 later stalls.
