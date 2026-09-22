# HANDOFF — PS4 13.52 Decrypted Kernel: 0-Day Audit

**Written:** 2026-09-22
**Author:** previous agent session
**Successor:** you. You are taking over a live, partially-complete investigation.
Read this file top to bottom before touching anything.

---

## 0. THE 60-SECOND VERSION

1. We spent ~2 days trying to decrypt the **14.00** kernel. **That is impossible** — the
   key is hardware-locked in the SAMU and the only software oracle refuses because of a
   firmware version gate. See §5 for the full proof. **Do not re-litigate this.**
2. Along the way we learned that the real path to a 14.00 exploit is a **FreeBSD kernel
   bug hunt** (the PS4 kernel is a FreeBSD 9 fork), and that **14.00 = 13.52 + 8 bytes**.
3. So we pivoted: we **dumped the full decrypted 13.52 kernel off the live console**. It
   worked, it's verified, and it's sitting in this folder.
4. **Your mission (§1)** is to audit that kernel for 0-day exploit chains.
5. There is a large **prior research tree** at `C:\Users\Kinan\Downloads\bd-j-usr\` with a
   real exploit chain and an explicit "blocked on a kernel dump" list (§4, §6). That list
   is now unblocked. Start there.

---

## 1. YOUR MISSION

> **Audit the full, fresh 13.52 kernel dump — every line — for potential 0-day exploit
> chains that lead to a jailbreak / kernel read+write access, most likely affecting 14.00
> in addition to 13.52.**

Constraints and clarifications, as given by the user:

* **Target property:** kernel read/write. Not a crash, not a DoS — an R/W primitive, or
  the first link of a chain that reaches one.
* **Scope:** the whole image. Genuinely exhaustive, not a grep for known CVEs.
* **Prefer findings likely to survive into 14.00.** Basis: 14.00's plaintext kernel image
  is `0x14a65f0` vs 13.52's `0x14a65e8` — **+8 bytes**, same load vaddr (`0x680000`), same
  entry point (`0x6ffff0`). So 14.00 is 13.52 with one small surgical patch. **Most 13.52
  bugs are expected to still be live in 14.00.** Caveats are in §5.6 — read them, they are
  real and you must not oversell a finding.
* **Confirmation method the user wants:** diff a finding against the **existing 13.52
  jailbreak chain, which Sony has since patched**. If your bug is *that* bug, it's dead.
  The chain lives at `C:\Users\Kinan\Downloads\bd-j-usr\` (§4). The GoldHEN payload is at
  `bd-j-usr\research\goldhen_port\src\goldhen.bin` (260,160 B).
* **Environment:** the user's own console, offline, for research. Failed attempts are
  recovered by rebooting. There is no downgrade path from 13.52.

---

## 2. THE ASSET — THE KERNEL DUMP

**Location (clean, self-contained folder — this is your working root):**

```
C:\Users\Kinan\Downloads\JV13.52\1352-KERNEL-HANDOFF\
    kmemfull.bin          28,468,712 B   <- THE DUMP
    kmemfull.txt          dump status report
    kernel_symbols.txt    196 recovered internal symbols
    kernel_strings.txt    72,910 printable strings w/ offsets
    authmgr_disasm.txt    272,046 B      <- objdump of 0x642300..0x644600
    HANDOFF.md            this file
    verify_kdump.py       validator (run this first)
    analyze_kernel.py     ELF/offsets/symbols/region map
    extract_symbols.py    recovers the embedded __func__ name tables
    resolve_strings.py    resolves rip-relative string refs from disasm
    check_roadmap_offsets.py   checks the prior roadmap's candidate RVAs
    find_sysent.py        sysent-base finder (see §7 — needs work)
    probe_self_shared.py  \ SELF-vs-SELF structural comparison
    probe_self_hdr2.py    / (13.52 vs 14.00, no keys needed)
    probe_pih.py, probe_pih2.py   Program Identification Header reader
    go_kmemfull.py        the deploy script that fired the dump
    14.00-KERNEL-DECRYPT-PLAN.md   the full write-up of the whole investigation (§1-20)
```

**Identity / integrity:**

```
size    28,468,712 B   (0x1b265e8)
sha256  206581e7fc65c3b635dbab3d8fb7611217d68768bd8db4d35972fd83b83bd102
```

`verify_kdump.py` -> **8/8 structural checks pass** (size, ELF magic, ELFCLASS64,
little-endian, `EI_OSABI==9` FreeBSD, `e_machine==0x3e`, the `ORBISYS` anchor at
`0x1520000` matching the v9 live probe, region behaviour).

**What it is and what it is not:**

* It is the **file-backed image**: `0x0 .. 0x1b265e8`. `.text` is `0x0 .. 0xcfe758`
  (13.6 MB). `.data` starts at `0x1520000`.
* It is the **post-relocation live image** — `e_phnum == 0`, VAs are absolute kernel VAs
  (this boot's kbase was `0xffffffffc5530000`). **Offsets in the file are kbase-relative**
  and stable; absolute VAs are not (KASLR changes per boot).
* It does **not** include runtime `bss` beyond `0x1b265e8` (where AuthMgr runtime structs
  like `0x269c0a0` live). That region is readable and can be captured separately with
  `go_kmemfull.py` + a `kmemfull.cfg` override, but it is runtime state, not code.

---

## 3. ENVIRONMENT & HOW TO RUN THINGS

### 3.1 The console

```
IP            172.20.10.3      <- may change; verify before deploying (hotspot DHCP)
BinLoader     9090             <- ONE-SHOT listener. Send exactly once.
                                  Never probe with connect/close, it can consume it.
Log stream    3232             <- LIVE ONLY, no replay. Attach BEFORE firing a payload.
FTP           2121             <- GoldHEN FTP. Fragile; dies on first data command.
                                  Avoid it. Prefer TCP payload delivery.
USB mount     /mnt/usb0        <- payloads read/write here. Must be FAT32.
```

Deploy pattern that works (see `go_kmemfull.py`):
attach 3232 reader -> wait 3 s -> send payload to 9090 once -> collect log -> pull USB.

`wait_goldhen.py` (in the parent dir) polls 2121/3232 until GoldHEN is back up.

### 3.2 Building PS4 payloads

Payloads are built with the **ps4-payload-sdk**, and there is **no compiler on the Windows
host** — you must build through Docker.

```powershell
# image already exists locally:
#   ps4-payload-sdk:latest   (616 MB)
docker run --rm --entrypoint make `
  -v "C:\Users\Kinan\Downloads\JV13.52\<YOUR_PAYLOAD_DIR>:/kmemfull" `
  -w /kmemfull ps4-payload-sdk:latest
```

Gotchas learned the hard way:

* **`--entrypoint make` is required.** The image's `/entrypoint.sh` has CRLF line endings,
  so `exec /entrypoint.sh` fails with *"no such file or directory"*. Always override it.
* Do **not** nest `/* */` inside a block comment in C source — it silently closes the
  outer comment and the build fails with a confusing parse error.
* `PS4SDK=/lib/ps4-payload-sdk` is set in the image; `libPS4.a` is prebuilt there.
* The payload's own `Makefile` in `kmemfull/` is a good template.

### 3.3 Disassembly

No objdump on the host either — use the SDK container:

```powershell
docker run --rm --entrypoint objdump -v "C:\Users\Kinan\Downloads\JV13.52:/w" `
  ps4-payload-sdk:latest -D -b binary -m i386:x86-64 `
  --start-address=0x642880 --stop-address=0x642c90 /w/kmemfull.bin
```

With `-b binary`, `--start-address`/`--stop-address` are **file offsets**, which equal
kbase-relative RVAs in this dump.

### 3.4 Host tooling

Windows, PowerShell 5.1 — `&&`/`||` are NOT supported, use `;`. Managed `python` is
available and is what all the `.py` scripts use. Docker 29.7.2 is available.

---

## 4. THE PRIOR RESEARCH TREE — READ THESE FIRST

**This is the most important section. There is ~2 months of prior work here and it is
directly relevant. Do not start the audit without reading these.**

Root: `C:\Users\Kinan\Downloads\bd-j-usr\` — a BD-J (Blu-ray Java) userland exploit tree,
and `bd-j-usr\research\` — the research archive.

### 4.1 Must-read documents, in priority order

| file | size | why it matters |
|---|---|---|
| `bd-j-usr\research\HANDOFF.md` | **249 KB** | the PRIOR handoff. Supersedes the roadmap. Read §0R and §30-§35 at minimum. |
| `bd-j-usr\research\ROADMAP_13_52.md` | 8.6 KB | research state + the "gap list for 13.52". Marked HISTORICAL, superseded by HANDOFF.md §0R + §30-§35, but the gap list is exactly what our dump unblocks. |
| `bd-j-usr\research\FULL_CHAIN_PLAYBOOK.md` | 12 KB | the end-to-end exploit chain. |
| `bd-j-usr\research\ps4-kernel-uaf-research-fw1352\CONSOLIDATED_FW1352_REPORT.md` | 8.8 KB | consolidated kernel UAF findings on 13.52. |
| `...\ps4-kernel-uaf-research-fw1352\FINDINGS.md` | 22 KB | the findings detail. |
| `...\ps4-kernel-uaf-research-fw1352\LIBKERNEL_ANALYSIS_REPORT.md` | 14 KB | libkernel analysis. |
| `...\ps4-kernel-uaf-research-fw1352\AGENTS.md` | **67 KB** | agent guidance for that sub-project. |
| `...\ps4-fw1352-kernel-research-paper\CONSOLIDATED_FW1352_REPORT.md` | 7 KB | a second, parallel 13.52 kernel report. |
| `bd-j-usr\research\OFFSETS_1352_DRAFT.md` | 2.2 KB | offset draft. |
| `bd-j-usr\research\SIMPLE_STEPS.md` | 7.2 KB | simplified step list. |
| `bd-j-usr\README.md` | 10.8 KB | the BD-J userland tree itself. |

### 4.2 The exploit chain as previously understood

From `ROADMAP_13_52.md` §"Real BD-J chain architecture" (proven <= 12.52; official GoldHEN
repo states Poops <= 13.00):

```
1. Burned BD-R runs an unsigned Xlet                    (BD-JB, CTurt 2015)
2. System.setSecurityManager(null)                      (3-line sandbox escape)
3. sun.misc.Unsafe                                      -> userland R/W
4. reflect ClassLoader$NativeLibrary                    -> dlsym bridge (libkernel handle 8193)
5. API.java: fake Klass/vtable + rebind Array.multiNewArray JNI fn-ptr
                                                        -> api.call(anyNativeAddr, args)
6. Poops.java: IPV6_RTHDR ip6_pktopts UAF
   netcontrol triple-free -> twins/triplets spray -> kqueue reclaim
   -> kl_lock/kq_fdp leak -> uio/iov races -> pipe-buffer corruption
   -> STABLE kread/kwrite
7. allproc found dynamically; kbase = kl_lock - KL_LOCK; ucred->root, prison0, rootvnode
8. sysent[661] hijack -> RWX mmap -> 661 "kexec" shellcode (LDR lstar defeat)
   -> per-FW patch blob -> BinLoader payload from USB
```

**Stage 6 is the kernel exploit. It is a network-stack UAF reachable from userland via
`setsockopt` — i.e. a serious, chainable kernel bug class.** Your audit should absolutely
consider whether this bug and its cousins still exist, and whether *different* bugs in the
same surface do.

**Key structural fact from the roadmap:** stages 1-7 are **offset-independent except
`KL_LOCK`**. Everything else (`sysent[661]`, the gadget, the 10 patch sites) is only needed
at the final patch step. That means **getting kernel R/W does NOT require correct key
offsets** — which is exactly why a bug hunt is worth doing.

### 4.3 The explicit "gap list for 13.52"

Verbatim from `ROADMAP_13_52.md`. **Our dump unblocks items 2, 3 and 4:**

1. WebKit anchor+gadgets for 13.5x — needs decrypted `libSceNKWebKit.sprx`.
   **DISPROVEN assumption:** the roadmap's later sweep established 13.5x shipped a NEW
   WebKit build (`POP_R8`/`POP_R9` gadgets present in 13.04, absent in 13.52). ~100 MB
   scanned. Browser-ROP route to 5/6-arg syscalls is blocked.
2. Verify `k_kl_lock` (assumed `0xE6C20`) — *"verifiable in seconds once kernel R/W lands
   ... or from a kernel dump."* **WE HAVE THE DUMP. See §6.1 — the assumed value FAILS.**
3. `k_sysent_661` / `k_jmp_rsi` — *"1350.bin provides candidates (0x01112470 / 0x47B31);
   verify against dump."* **See §6.2 / §6.3 — both candidates FAIL as given.**
4. Generate patch blob `1352.bin` from the dump by pattern-matching the 10 sites
   (`1300.bin` has the 314-byte 10-site reference format). **Now possible.**
5. Payload: a HEN built for 13.5x.

### 4.4 The CTAP patch format (from `patches/1350.bin`, decoded)

```
magic "CTAP", ver 1, count 4, then 4 x 16-byte records (addr:u64, val1:u32, val2:u32)
  #  addr (RVA)   meaning                          val
  1  0x01112470   sysent[661] entry (13.50)        0
  2  0x01112478   sysent[661].sy_call              1 / 1 flags
  3  0x01112480   sysent[661]+0x10                 0
  4  0x00047B31   jmp rsi gadget (from 13.02)       0xE6FF  (ff e6 = jmp rsi)
```

### 4.5 Other artEFacts worth knowing

| artefact | path |
|---|---|
| GoldHEN payload (the 13.52 jailbreak) | `bd-j-usr\research\goldhen_port\src\goldhen.bin` (260,160 B) |
| GoldHEN release archive | `bd-j-usr\research\goldhen_port\GoldHEN_v2.4b18.7z` |
| GoldHEN payload from the chain | `C:\Users\Kinan\Downloads\payload.bin` (499,776 B = GoldHEN 2.4b18.7) |
| Real chain source | `bd-j-usr\research\chain_poops.mjs` (134,585 B) |
| Kernel offsets DB | `bd-j-usr\research\ps4_offsets.mjs` (29,566 B) |
| Candidate patch blobs | `bd-j-usr\research\patches\` (`1350.bin`, `1300.bin`) |
| Poopsploit Lua variant | `bd-j-usr\research\Poopsploit-Lua\poopsploit.lua` |
| VueAfterFree exploit | `bd-j-usr\research\vue-after-free\` |
| BD-JB userland | `bd-j-usr\research\BD-UN-JB\` |
| HENloader real source | `bd-j-usr\research\HENloader_Source\` + `bd-j-usr\research\henloader_lp\` |
| Telemetry from live runs | `bd-j-usr\research\telemetry.log` (4.9 MB) |
| Console log tool | `bd-j-usr\research\spy_server.py` |
| 13.52 kernel research paper | `bd-j-usr\research\ps4-fw1352-kernel-research-paper\` |
| 13.52 kernel UAF research | `bd-j-usr\research\ps4-kernel-uaf-research-fw1352\` |

**⚠ WARNING from the roadmap:** the **uploaded repo `bd-j-usr` / "HENloader MX" is FAKE.**
Its `external/KernelOffset.java` fabricates offsets (13.50 offsets = 13.00 + 0x10000, a
uniform shift that never happens in real kernels; `sysent` identical across four firmwares).
Its one plausible value was lifted from `patches/1350.bin`. **The real base is
`bd-j-usr\research\HENloader_Source\` + `GoldHEN\henloader_lp`.** Do not trust
`bd-j-usr`'s top-level Java sources.

---

## 5. WHAT THIS SESSION ESTABLISHED (the 14.00 investigation)

Full write-up: `14.00-KERNEL-DECRYPT-PLAN.md` (in this folder), sections 1-20. Summary:

### 5.1 You cannot decrypt the 14.00 kernel from a 13.52 console. Settled.

Three independent, verified walls:

* **The key is hardware.** Per-console key material lives in **SNVS / the SAMU**; the scene
  states directly that *"it is impossible to extract any keys so that decryption could be
  done externally."* Nothing running on the APU can read it.
* **The oracle refuses.** The documented method (psdevwiki, *SELF - SPRX*) is to use your
  own console as a blackbox decrypter, with conditions: valid signature, **required FW
  lower than the console's FW**, key_revision matching. Measured from the 14.00 SELF header:
  the 14.00 kernel declares **System SW Version = BCD 0x1400 (14.00)**; the console is
  **0x1352 (13.52)**. **14.00 > 13.52 -> condition fails.**
* **Brute force is 2^128.** At a generous 10^9 keys/s that is 1.1e22 years (~7.8e11 age-of-
  universe-times); realistically the test rate is ~10^3 keys/s because each candidate needs
  a full 10.87 MB decrypt + decompress, giving ~7.2e27 years.

Also settled: **14.00 has no public jailbreak**; theflow found the bug, reported it to
Sony, and 14.00 patched it.

### 5.2 The one thing that would work, and why it's the same wall

If you had a console running **>= 14.00 with an exploit**, you would not decrypt the SELF at
all — you would **dump the running kernel from RAM**, exactly as we did for 13.52. So
decryption is never the bottleneck. **A 14.00 kernel exploit is.** And that is not secret
knowledge — see §7.

### 5.3 Measured: 14.00 is 13.52 + 8 bytes

| field | 13.52 | 14.00 |
|---|---|---|
| SELF `key_type` (key bank) | `0x0c01` | `0x0c01` (same) |
| embedded ELF | ELF64/x86-64/ET_EXEC | same |
| `e_entry` | `0x6ffff0` | `0x6ffff0` (same) |
| phdr vaddr / align | `0x680000` / `0x1000` | same |
| **phdr filesz = memsz** | **`0x14a65e8`** | **`0x14a65f0` (+8)** |
| SELF file size | 10,866,322 | 10,867,186 (+864, compressed) |

The payload is **compressed before encryption** (filesz 21.65 MB vs a ~10.87 MB container),
which is why 332 probes of 96 bytes from the 13.52 body found **zero** matches in 14.00 —
one changed instruction cascades through the whole compressed stream.

### 5.4 Free, in the clear, from the 14.00 SELF

SHA-256 of the **decrypted 14.00 ELF** sits in the SELF header at offset `0xE0`:

```
a66914240c545e47b2850cc09690e010faa753e939db90245e224b3d3fc9e38e
```

That is a free **verification oracle** — if a 14.00 kernel decryption ever surfaces, you can
confirm it instantly. (13.52's equivalent is
`4cbd3e251c87b591f4b3398161628e2b902c6ae9050ff157c73de40fb1969fe3`.) It cannot help
*recover* a key.

### 5.5 How a 14.00 exploit would actually be built

```
Run 14.00 -> userland entry -> fuzz for a kernel bug -> kernel R/W -> dump RAM
```

* **Userland entry for 14.00 largely exists**: the **Lua save exploit still works on the
  latest firmware**; also BD-JB, Mast1c0re (PS2 emu), Netflix-N-Hack, WebKit. Caveat from
  consolemods' exploit chart: the kernel stage needs a **privileged** userland context
  (WebKit / Vue / PS2 emu / BD-JB) — Lua alone does not grant it.
* **The kernel bug is found by fuzzing and black-box research, not by reading source you
  don't have.** The kernel is a FreeBSD fork with public source.
* **Tooling has changed recently.** Praetorian's *FreeBSoD* (Jun 2026) found ~8 FreeBSD
  kernel vulns in days and 2 working exploits in a weekend on a **~$100/month** Claude
  account. Method: build a pattern DB from public writeups -> have the agent write
  **CodeQL/semgrep** rules -> LLM triage -> **close the loop with a KASAN FreeBSD VM as an
  oracle**. They cite the PS4/PS5 scene explicitly. Their documented failure modes are real
  and you must guard against them: false positives, **sycophancy**, and the model
  *"cheating"* (patching the kernel to make a bug triggerable). Mitigations: custom harness,
  a **judge/peer LLM**, strict acceptance criteria.
* Example bug class they found: `sys/net/rtsock.c` `rtsock_msg_buffer()` — user-controlled
  `sa_len` copied into a 128-byte stack `sockaddr_storage`; the guarding KASSERT **compiles
  out in production**; `RTM_GET` is **exempt from `PRIV_NET_ROUTE`**, so any unprivileged
  local user can trigger it. That is the shape of thing to look for: **stack/heap overflow
  or UAF in a syscall/ioctl path reachable without privilege.**

### 5.6 HONEST CAVEATS — do not oversell a finding

1. **We cannot localise the 14.00 patch.** Both bodies are encrypted+compressed; there is no
   diff. `+8 bytes` is a *size* fact, not a *content* diff.
2. **Size-neutral fixes are invisible.** A patch that swaps one instruction for another of
   equal length gives a **zero** delta. So 8 bytes bounds the *net* size change, not the
   *number* of fixes.
3. **14.00 specifically patched theflow's hypervisor bug.** If your 0-day *is* that bug
   (or the Poops bug, which Sony long ago fixed), it is dead. Diff against the known chain.
4. **"Affects 14.00" != "exploits 14.00".** You still need a privileged userland entry.
5. **A KASAN FreeBSD 9 VM proves a bug exists in FreeBSD 9. It proves nothing about 14.00.**
   Those are different questions.
6. **The only way to confirm a bug survives into 14.00** is to trigger it on a real 14.00
   console (crash observation needs no decryption), which costs the user the jailbreak on
   that box. Budget for that.

---

## 6. VERIFICATION OF THE ROADMAP'S OPEN OFFSETS — RESULTS

I ran `check_roadmap_offsets.py` and `find_sysent.py` against the dump. **Three of the
roadmap's assumed values FAIL. This is a real finding: 13.52 is NOT offset-compatible with
the 13.50/13.02-derived assumptions.**

### 6.1 `k_kl_lock` — assumed `0xE6C20` — **FAILS**

`0xE6C20` is **inside `.text`** (`.text` ends at `0xcfe758`), and the bytes there are
**code**, not a lock object:

```
0xE6C20:  00 48 89 47 28 48 0f 45 f1 4d 85 c0 48 8d 0d 7d 00 00 00 ...
                      48 89 47 28 = mov [rdi+0x28], rax ... 5d c3 = pop rbp; ret
```

`KL_LOCK` is supposed to be a **data** offset (it is used as `kbase = kl_lock - KL_LOCK`
from a leaked kqueue lock address). A `.text` offset cannot be that. **The assumed value is
wrong for 13.52, or the base convention differs. Re-derive it.**

### 6.2 `k_jmp_rsi` — candidate `0x47B31` — **FAILS**

```
0x47B31:  00 27 00 eb 11 48 89 df      <- not ff e6
```

There are **exactly 20 occurrences of `ff e6` (jmp rsi) in `.text`**, at:

```
0x2b1b8  0x31db8  0x3283f  0x3c2dc  0x70ac5  0x70add  0x82c8e  0x8e042
0x17cb93 0x1a0efc 0x1a9a6a 0x228d1c 0x2336ef 0x2337dc 0x233b0d 0x233b76
0x233bd3 0x233e0c 0x233e72 0x233ec7
```

The gadget exists; the candidate offset does not. **Pick a live one and verify it is a
usable, non-guarded `jmp rsi` in a suitable context.**

### 6.3 `k_sysent_661` — candidates `0x1112470` / base `0x110a880` — **PARTIAL / SUSPECT**

A very sysent-shaped table **does** exist at `0x110a880` (stride `0x30`, `+0x00` = small
int, `+0x08` = a kernel `.text` pointer):

```
sysent[0] @0x110a880  narg=2  sy_call=0xffffffffc580a6a0
sysent[1] @0x110a8b0  narg=2  sy_call=0xffffffffc564f6d0
sysent[2] @0x110a8e0  narg=5  sy_call=0xffffffffc56519c0
sysent[3] @0x110a910  narg=4  sy_call=0xffffffffc56524a0
sysent[4] @0x110a940  narg=4  sy_call=0xffffffffc572ff60
sysent[5] @0x110a970  narg=3  sy_call=0xffffffffc56e8b10
```

**But two things are wrong:**

* `sysent[661]` at `0x110a880 + 661*0x30 = 0x1112470` reads three near-adjacent `.text`
  pointers (`0xffffffffc5e4bba1`, `...bbab`, `...bbb5`), which is **not** a sysent entry
  shape (no small narg at `+0x00`).
* **The classic FreeBSD low-syscall narg signature does not appear anywhere.** I scanned
  `0xA00000..0x1400000` for `narg[1..9] == (1,0,3,3,3,1,4,2,2)` (exit/fork/read/write/open/
  close/wait4/creat/link) requiring all `sy_call` in kernel text — **zero candidates.**

**Conclusion:** the region at `0x110a880` is *a* table of `{int, ptr}` records but is
**not** the stock FreeBSD `sysent` in the expected form, or its base/stride differ, or PS4's
sysent uses a different layout. **`find_sysent.py` is the starting point but needs its
signature relaxed** — try other strides (0x20/0x28/0x38), try dropping the assumption that
the table starts at syscall 0, and try identifying the table from a known syscall instead
(e.g. find `SYS_setsockopt` by its argument count and caller).

### 6.4 Net effect

**Do not trust any inherited 13.5x kernel offset.** The dump is now the source of truth.
Every offset the chain needs must be re-derived from `kmemfull.bin` and cross-checked
against live behaviour.

---

## 7. THE AUDIT PLAN — HOW TO ACTUALLY DO THE MISSION

Two workstreams. **Do A first** — it's fast, concrete, already half-done, and it validates
your whole toolchain. Then B, which is the real mission.

### Workstream A — re-derive the chain's offsets from the dump (hours, not weeks)

Everything the existing chain needs can now be computed statically. This is item 2/3/4 of
the roadmap's gap list and it validates that your dump-reading pipeline is correct.

1. **`k_kl_lock`** — find the kqueue lock object. Approach: `kqueue` struct layout is FreeBSD
   (`kq_fdp`, `kq_lock`). Search `.data` for a plausible lock (a `struct mtx`/`sx` is
   `{ void *lock_object; uintptr_t lock_data; }` with a recognizable name pointer nearby),
   near kqueue-related statics. Cross-check by grep'ing `kernel_strings.txt` for
   `kq_`, `kqueue`, `kl_` and resolving who references them.
2. **`k_jmp_rsi`** — choose from the 20 verified `ff e6` sites in §6.2. Prefer one that is
   a clean leaf gadget (preceded by `pop`/`ret`, not inside a JUMP_TABLE or a guarded block).
   Verify by disassembling a window around each with the objdump command in §3.3.
3. **`sysent` base and `sysent[661]`** — fix `find_sysent.py` (§6.3). Then verify by
   matching a *known* syscall: find the function that is the `write(2)` handler by
   cross-referencing the `SYS_write` argument count and its callers, and walk backwards.
4. **The 10 patch sites for `1352.bin`** — use `patches/1300.bin` (314 bytes, 10 sites) as
   the reference format, and pattern-match each site into the dump. Emit a CTAP file (§4.4).

Deliverable: a `1352_offsets_verified.md` + a `1352.bin` CTAP blob, each value annotated with
the evidence from the dump.

### Workstream B — hunt for NEW 0-days (the actual mission)

**Step B1 — build the analysis substrate.**
* Symbol recovery is **already done for the SBL subtree**: `kernel_symbols.txt` has 196
  names recovered from contiguous `__func__` tables sitting next to each module's
  `W:\Build\J02697906\sys\internal\modules\...` path. **The same trick generalises** —
  `extract_symbols.py` scans one window; widen it (`LO, HI`) across the whole image to pull
  far more names. This is the single highest-leverage thing you can do: it converts an
  anonymous 13.6 MB of x86-64 into labelled code.
* Build a **string → xref index**. `kernel_strings.txt` already has 72,910 strings with
  offsets; `resolve_strings.py` shows how to turn a disassembled `lea rXX, disp(%rip)` back
  into a string. Do this systematically to label functions by the messages they print.
* Recover **function boundaries** by scanning `.text` for `push rbp; mov rbp,rsp` prologues
  and the matching epilogues, and correlate with the `__func__` strings.

**Step B2 — get the FreeBSD 9 source as the diff base.**
The kernel identifies as `Copyright (c) 1992-2012 The FreeBSD Project` and
`FreeBSD ELF64`. FreeBSD 9.x source is public. Align PS4 functions to FreeBSD 9 functions
(the `__func__` tables and the distinctive strings make this tractable). **Then the audit
becomes: where did Sony fail to merge a security fix, and where is the code simply wrong.**

**Step B3 — prioritise by reachability. This is the most important strategic decision.**
A bug only matters if a userland exploit can reach it. Rank targets by *can an unprivileged
userland process trigger this*:

1. **The network stack.** This is where the known chain lives (`IPV6_RTHDR` / `ip6_pktopts`
   / `setsockopt` — reachable unprivileged, the roadmap calls it a triple-free UAF). Audit
   *neighbouring* code and the rest of `netinet6`: options parsing, mbuf handling, `uio`/
   `iov` handling, `fragment`/`reassembly`, `nd6`. Same bug family, different entry points.
2. **`kqueue`** — used as the reclaim primitive in the known chain. Audit its allocation/
   free paths.
3. **Pipes, `uio`/`iov`, `sendmsg`/`recvmsg` ancillary data** — classic UAF country and
   explicitly named in the known chain.
4. **Syscall argument handling generally** — missing `copyin` size checks, integer
   truncation feeding an allocation, TOCTOU on user pointers, unchecked `*_len` fields.
   The `rtsock_msg_buffer` shape from §5.5 is the template: a length field driving a copy
   into a fixed stack buffer.
5. **Filesystems** (`devfs`, `msdosfs`, `exfat`) — reachable via mountable USB media and
   through image parsing.
6. **Only later: the SBL / AuthMgr surface.** It is heavily hardened, and per §5.1 the SELF
   path needs privileged access — but `_sceSblAuthMgr...` and `verifyHeader` /
   `decryptSelfBlock` / `loadSelfSegment` are now **named** and worth reading once the cheap
   targets are exhausted.

**Step B4 — run the pattern hunt.**
Use the Praetorian methodology (§5.5): write **semgrep/CodeQL-style rules** for the bug
classes above against the FreeBSD 9 source, and separately pattern-scan the binary itself
for the compiled signatures (unchecked `memcpy`/`bcopy` with a user-controlled length,
`malloc` with a multiplied size, `free` on an error path after a successful `copyin`, etc.).
`libPS4`-style static scanners are not enough — write targeted rules.

**Step B5 — verify with an oracle you actually trust.**
Stand up a **KASAN FreeBSD 9 VM** and reproduce. Remember §5.6#5: this proves the bug is
real in FreeBSD 9, it does **not** prove it survives in 14.00.

**Step B6 — triage honestly.**
Guard against the documented failure modes: false positives, **sycophancy** (don't accept a
finding because it's exciting), and self-cheating (don't patch the kernel to make a PoC
work). Use a second model or a checklist as a judge. Reject anything you cannot reproduce
from a cold boot.

**Step B7 — cross-check against the known chain.**
Before reporting anything, ask: *is this the Poops `ip6_pktopts` bug, or the WebKit bug, or
theflow's HV bug?* Those are patched. If it is one of them, discard it. **This is the
confirmation step the user explicitly asked for** — the chain to diff against is at
`bd-j-usr\research\` (§4), with the GoldHEN payload at
`bd-j-usr\research\goldhen_port\src\goldhen.bin`.

### Workstream C — the 14.00 question, if you get that far

Once you have a candidate: confirm it is **reachable from a 14.00-available privileged
userland context**, then either test it on a sacrificed 14.00 console (crash observation,
no decryption needed) or hand it to someone who will. **Do not claim it affects 14.00
without that test** — see §5.6.

---

## 8. COMPLETE FILE MAP

### 8.1 Your working root (this folder)
```
C:\Users\Kinan\Downloads\JV13.52\1352-KERNEL-HANDOFF\
  HANDOFF.md                      <- you are here
  kmemfull.bin                    THE DUMP (28,468,712 B)
  kmemfull.txt                    dump status
  kernel_symbols.txt              196 symbols
  kernel_strings.txt              72,910 strings
  authmgr_disasm.txt              disassembly
  verify_kdump.py / analyze_kernel.py / extract_symbols.py / resolve_strings.py
  check_roadmap_offsets.py / find_sysent.py
  probe_self_shared.py / probe_self_hdr2.py / probe_pih.py / probe_pih2.py
  go_kmemfull.py
  14.00-KERNEL-DECRYPT-PLAN.md    full investigation write-up
```

### 8.2 Parent workspace
```
C:\Users\Kinan\Downloads\JV13.52\
  kmemfull\                       payload source + Makefile + include/offsets_1352.h
  kmemdump\                       the earlier probe payload (v10) + offsets_1352.h
  dec\1352\                       the seven 13.52 SELF modules from the PUP (ENCRYPTED)
  dec\80010002_kernel_14.00.self  the 14.00 kernel SELF (ENCRYPTED)
  orbital-ref\                    AlexAltea/orbital clone (self_decrypter.c lives here)
  ps4-re-utilities\               Al-Azif utilities (split-kernel.py etc.)
  ps5-selfdec-ref\                PS5 self-dec reference
  pulled\ recovered\ probe\ sdk\  earlier work
  1352-AUTHMGR-REOPEN.md          42 KB  AuthMgr RE notes
  1352-SBL-OFFSETS.md             30 KB  SBL offset notes
  1352-OFFSET-DERIVATION.md       4.4 KB offset derivation
  14.00-KERNEL-ROUTE.md           9.8 KB earlier route doc
  authheader.txt                  60 KB  auth header analysis
  xref_out.txt / xref_strings_1352.py   existing xref work
```
(There are ~250 more `.py`/`.txt`/`.md` files in this directory from earlier sessions —
list it before assuming something doesn't exist.)

### 8.3 The prior research tree (see §4)
```
C:\Users\Kinan\Downloads\bd-j-usr\
C:\Users\Kinan\Downloads\bd-j-usr\research\
C:\Users\Kinan\Downloads\bd-j-usr\research\goldhen_port\src\goldhen.bin   <- THE JAILBREAK
C:\Users\Kinan\Downloads\payload.bin                  GoldHEN 2.4b18.7, 499,776 B
```

### 8.4 The console
```
172.20.10.3 : 9090 (BinLoader, one-shot) / 3232 (live log) / 2121 (FTP, avoid)
USB -> /mnt/usb0
```

---

## 9. REFERENCES

**Primary technical sources found this session (all verified by fetching):**

* psdevwiki, *SELF - SPRX* — SELF format, the blackbox decryption method and its conditions:
  https://www.psdevwiki.com/ps4/SELF_-_SPRX
* psdevwiki, *KeySlots* — slot table (KCA per-console / KGA global, slot 6 IPL layer):
  https://www.psdevwiki.com/ps4/KeySlots
* psdevwiki, *Keys* — key derivation:
  https://www.psdevwiki.com/ps4/Keys
* consolemods, *PS4:Exploit_Chart* — which userland/kernel stages work on which firmware:
  https://consolemods.org/wiki/PS4:Exploit_Chart
* consolemods, *PS4:Firmware_Revert* — downgrade mechanics / syscon:
  https://consolemods.org/wiki/PS4:Firmware_Revert
* Praetorian, *FreeBSoD* — AI-assisted FreeBSD kernel bug hunting, the methodology in §5.5:
  https://www.praetorian.com/blog/ai-vulnerability-research-freebsd-kernel/
* fail0verflow, *PS4 Aux Hax 5* (PSVR / Marvell 88DE3214 / FIGO — note: **not** the PS4 APU):
  https://fail0verflow.com/blog/2022/ps4-psvr/
* psxhax, *PS4 Module Dumper payload (SocraticBliss)*:
  https://www.psxhax.com/threads/ps4-module-dumper-payload-for-dumping-decrypting-by-socraticbliss.7176/
* psxhax, *PS4 Glitch Pinout / downgrading* — the syscon glitch thread; note the
  SNVS / "only SAMU modules access the per-console keys" claim (staff flagged the thread for
  misinformation, so treat as corroboration only):
  https://www.psxhax.com/threads/playstation-4-glitch-pinout-ps4-slim-pro-downgrading-update.1398/
* nextgenupdate, *Understanding The PS4 Processor SAMU*:
  https://nextgenupdate.com/forums/ps4-mods-cheats/955252-understanding-ps4-processor-samu.html
* r/ps4homebrew, the SAMU key-slot exploit (flatz, Dec 2021):
  https://www.reddit.com/r/ps4homebrew/comments/rjbzq6/newly_discovered_exploit_could_allow_samu_keys_to/

**Code / tools:**

* `Scene-Collective/ps4-kernel-dumper` — "dumps your device's kernel from memory to a USB
  device"; the canonical memory-dump approach: https://github.com/Scene-Collective/ps4-kernel-dumper
* AlexAltea/orbital — `self_decrypter.c`, the blackbox SELF decrypter:
  https://github.com/AlexAltea/orbital/blob/master/tools/dumper/source/self_decrypter.c
  (a clone is at `..\orbital-ref\`)
* `GoldHEN/GoldHEN_Plugins_Repository` — GoldHEN plugin system (plugins are `.prx` in
  `/data/GoldHEN/plugins/`, listed in `plugins.ini`): https://github.com/GoldHEN/GoldHEN_Plugins_Repository
* Al-Azif/ps4-re-utilities — clone present at `..\ps4-re-utilities\`
* `mansoor0x/polpNO-use` — the real chain (`chain_poops.mjs`, `ps4_offsets.mjs`)
* `iaceene/HENloader_Source` — real HENloader base

**Local reference clones already on disk:** `..\orbital-ref\`, `..\ps4-re-utilities\`,
`..\ps5-selfdec-ref\`, `..\sdk\`.

---

## 10. HARD-WON LESSONS — READ THIS BEFORE WASTING A DAY

1. **Do not re-litigate the 14.00 SELF decryption.** §5.1 is settled and proven. An earlier
   session burned a lot of time on it three separate times. It is not reachable.
2. **Do not trust inherited 13.5x offsets.** §6 shows three of them are wrong for 13.52.
   The dump is the source of truth now.
3. **The uploaded `bd-j-usr` top-level Java sources are FAKE.** See §4.5. Use
   `research/HENloader_Source/`.
4. **Console deploy discipline:** attach 3232 *before* firing; send to 9090 *exactly once*;
   never probe 9090; avoid FTP 2121. `go_kmemfull.py` is the working template.
5. **Chunk size 0x1000 (4096 B) is proven safe** for `get_memory_dump()`. A 128 KiB copyout
   **killed the console** in an earlier attempt. Never raise it without a ladder.
6. **Docker build gotchas:** `--entrypoint make` is mandatory (CRLF shebang); never nest
   `/* */` in a block comment.
7. **Size != content.** Do not claim a change is "8 bytes" as though you diffed it. You did
   not. See §5.6.
8. **The image is compressed-then-encrypted.** Identical plaintext regions produce
   completely different ciphertext. You cannot diff SELF bodies.
9. **Progress is resumable by design.** `kmemfull` writes incrementally; a softlock costs
   only the remainder. Keep that property in any new payload you write.
10. **Beware sycophancy in yourself.** The user is highly motivated and would love a yes. The
    value you add is honest negative results. Several times in this project the honest answer
    was "no, and here is the measurement proving it."

---

## 11. OPEN QUESTIONS & IMMEDIATE NEXT ACTIONS

### Immediate (do these first, in order)
1. Run `verify_kdump.py` to confirm your copy of the dump is intact
   (expect `8/8`, sha256 `206581e7...3bd102`).
2. Read `bd-j-usr\research\HANDOFF.md` §0R and §30-§35, then `ROADMAP_13_52.md`.
3. Read `ps4-kernel-uaf-research-fw1352\CONSOLIDATED_FW1352_REPORT.md` and `FINDINGS.md` —
   a prior kernel UAF hunt on 13.52 already exists there. **Do not duplicate it.**
4. Fix `find_sysent.py` (§6.3) and re-derive the three broken offsets (§7 Workstream A).

### Open questions
* **Is the `0x110a880` table `sysent` at all?** §6.3. The narg signature fails. Resolve this
  before building anything on top of it.
* **~~What is the base convention of the roadmap's "RVA"s?~~ RESOLVED.** I tested the
  segment-relative hypothesis (`+0x680000`, i.e. the SELF's `p_vaddr`) with
  `test_base_convention.py`. **It is refuted.** With the shift:
  `0x47B31+0x680000 = 0x6c7b31` reads `ff 48 83 c4 08 5b 5d c3` (a function *epilogue*,
  not `jmp rsi`), and the sysent candidates at `+0x680000` become pure noise
  (`narg=-1694148767`, `sy_call=0x95a961cc716b137d`).
  **Conclusion: the image is one flat kbase-relative space and kbase-relative is the
  correct convention** (the sysent-shaped table is valid at `0x110a880` and garbage at
  `+0x680000`, which proves it). Image offset `0x680000` is simply `.text`. So the
  roadmap's three candidate *values* are genuinely wrong for 13.52 — not a base artefact.
  Re-derive them (§7 Workstream A).
* **What are the two entropy-8.000 spans** at `0xe00000..0x11fffff` and
  `0x1400000..0x17fffff` inside the image? Normal kernel code/rodata is 6.0-7.3. These look
  like embedded compressed or encrypted blobs. Unexplained — worth identifying, because
  embedded blobs are often parsed by weakly-validated code.
* **Did the `rtsock_msg_buffer` bug class (per-user `sa_len` -> 128-byte stack buffer,
  `RTM_GET` exempt from privilege) survive in the PS4 kernel?** FreeBSD 9-era code may well
  contain the ancestor of CVE-2026-3038. **Check this early** — it is high-value,
  unprivileged, and directly in the audit's sweet spot.
  **PARTIALLY ANSWERED by `probe_bug_classes.py`:** the subsystem **is present** —
  `rtsock` at `0x7becb1` / `0x7bed0d` / `0x7bed90`, `route_output` at `0x7bed99`,
  `rt_msg` at `0x7bed2d`. The specific function name is not a string (production kernels
  strip those), so locate it by resolving xrefs to those strings. Also confirmed present:
  **`priv_check` at `0x7a3574` and `suser` at `0x7a3592`** — so privilege *gating* is
  auditable, which is exactly what you need to prove a path is reachable unprivileged.
  Other confirmed-present surfaces: `kqueue`, `copyin`/`copyout`, `uio`/`iov`,
  `sendmsg`/`recvmsg`/`msgsnd`, `pipe`, `kevent`, `devfs`, `msdosfs`, `exfat`.

### Standing constraint
Everything here is the user's own console, offline, for research. Failed attempts are
recovered by reboot. There is no downgrade path from 13.52.

---

*End of handoff. The dump is real, verified, and the offsets are now yours to derive.*

---

# 12. UPDATE — the RawGame4 WebKit jailbreak, and what it revealed

The user supplied the **exact jailbreak used on the console**:
`C:\Users\Kinan\Downloads\raw13g.github.io-main.zip` (650,115 B), extracted to
`1352-KERNEL-HANDOFF\raw13g-webkit-jb\raw13g.github.io-main\`.

This is the reference chain the mission says to diff findings against. It is the
`rawgame4.github.io` WebKit exploit that consolemods' chart lists for 13.50.

## 12.1 What is in it

| file | size | what |
|---|---|---|
| `ps4_offsets.js` | 17,675 | **the authoritative per-firmware offset table** |
| `patches/1352.bin` | 632 | **the actual 13.52 kernel patch blob** |
| `patches/1350.bin`, `patches/1302.bin` | 632 | the same blob for other firmwares |
| `jb.js` | 104,194 | the exploit driver |
| `core.js`, `mem.js`, `int64.js`, `rpc_worker.js` | — | JSC + kernel R/W primitives |
| `goldhen.bin`, `payload2.bin` | 293,120 | GoldHEN payload (note: **293,120 B here**, vs the 260,160 B copy at `bd-j-usr\research\goldhen_port\src\goldhen.bin`) |
| `jb.html`, `index.html` | — | entry pages |

**This confirms the mission's premise end to end:** a WebKit (browser) userland entry
feeding a kernel bug, with a per-firmware patch blob, replacing the payload with the
GoldHEN HEN. It is exactly the "existing jailbreak which they fixed".

## 12.2 CORRECTION to §6 — I checked the wrong firmware's values

§6 tested `k_jmp_rsi = 0x47b31` and `k_kl_lock = 0xe6c20`. **Those are 13.50's values.**
`ps4_offsets.js` defines `PS4["13.52"]` as `Object.assign({}, PS4["13.50"], {...})` with
explicit overrides:

```js
k_jmp_rsi : 0x4d6d0      // NOT 0x47b31
k_kl_lock : 0xe6c60      // NOT 0xe6c20
k_evf_cv  : 0x785228
k_sysent  : 0x1102b70    // the sysent TABLE BASE
k_sysent_661 : 0x110a760 // = k_sysent + 661*0x30   <- internally consistent
k_sysctl_handle_int : 0x3fa8e0
k_idt_rsvd : 0x1c1e00
k_prison0 : 0x1a5c0c0    k_rootvnode : 0x2136e90
k_oid_kern_file 0x1a2f8a0 / maxfilesperproc 0x1a2f950 / maxprocperuid 0x1a3ba88 / maxfiles 0x1a2f9a8
k_arg1_maxfilesperproc 0x22cc47c / maxprocperuid 0x22cc478 / maxfiles 0x22cc474
```

**So §6.1/§6.2's "FAILS" verdicts were testing 13.50 values against a 13.52 kernel** — they
are not evidence that the 13.52 offsets are wrong. The roadmap's `1350.bin`-derived numbers
were simply 13.50 numbers, which is consistent. **Treat §6.1/§6.2 as superseded by this
section.** §6.3's sysent analysis is also reframed: `0x110a760` is *not* the table base, it
is `sysent[661]`; the base is `0x1102b70`.

## 12.3 THE BIG FINDING — our dump and the chain use different layouts

The chain's offsets do **not** index our dump directly. Measured with the `ORBISYS` anchor:

```
ORBISYS in OUR dump (kmemfull.bin) : 0x1520000
ORBISYS in the reference 1352k.elf : 0x0d20000
                          shift      +0x800000
```

And over the overlapping region, **73.2% of 4 KiB blocks are byte-identical** — same
kernel, different container.

**Why:** they are different *artefacts* of the same kernel.

* **Ours** (`kmemfull.bin`) is a **flat live memory image** at this boot's KASLR base
  (`0xffffffffc5530000`), starting at image offset 0. `e_phnum = 0`.
* **The reference `1352k.elf`** is a **proper ELF container**: `e_type=ET_EXEC`,
  `e_machine=0x3e`, `e_entry=0xffffffff8226a410`, **`e_phnum = 6`**, normalised to the
  fixed base `0xffffffff82200000`.

**Consequence — do this before trusting any inherited offset:** establish the mapping
between (a) the chain's RVAs, (b) the reference ELF's virtual addresses, and (c) our flat
image offsets. The `+0x800000` ORBISYS shift is the first anchor; find at least two more
(the `.text` start and a known string) before deriving a formula. Do **not** assume
`offset == RVA`.

A concrete check that is still open: with the naive `offset == RVA`, `k_jmp_rsi = 0x4d6d0`
holds `ff 26` (`jmp [rsi]`), **not** `ff e6` (`jmp rsi`). `ff 26` is still a usable pivot
(dereference-then-jump to attacker-controlled memory), so this may be a naming looseness
rather than an error — but resolve it against the mapping before building on it.

## 12.4 Our dump is INCOMPLETE for the chain

The chain references offsets **beyond our dump's end**:

| symbol | offset | in our dump? |
|---|---|---|
| `k_prison0` | `0x1a5c0c0` | yes |
| `k_oid_*` | `0x1a2f8a0`, `0x1a2f950`, `0x1a3ba88`, `0x1a2f9a8` | yes |
| **`k_rootvnode`** | **`0x2136e90`** | **NO** |
| **`k_arg1_maxfiles`** | **`0x22cc474`** | **NO** |
| **`k_arg1_maxprocperuid`** | **`0x22cc478`** | **NO** |
| **`k_arg1_maxfilesperproc`** | **`0x22cc47c`** | **NO** |

Our dump covers `0x0..0x1b265e8` (28.5 MB). The chain needs at least `0x22cc47c` — **short
by `0x7a5e94` (~7.6 MiB)**. And `ps4_offsets.js`'s own status line says the reference was
**"kdump5 tier1 36MB"** — i.e. `0x2400000`.

The dump also contains **40,446 kernel pointers**, with the highest target at `0x278f820`,
so the mapped space extends further still.

**ACTION: run a second pass** with `go_kmemfull.py` plus a `kmemfull.cfg`:
```
start=0x1b265e8
end=0x2400000
chunk=0x00001000
```
(`0x1000` is proven safe; see §10.5.) That closes the gap to the reference's 36 MB.
Consider extending to `0x2800000` for headroom.

## 12.5 The patch blobs are raw x86-64 shellcode, not CTAP

This contradicts §4.4. `patches/1352.bin` is **632 bytes of machine code**, and all three
firmware blobs are **identical except for one embedded address**:

```
b9 82 00 00 c0        mov ecx, 0xc0000082     ; MSR_LSTAR
0f 32                 rdmsr
48 c1 e2 20           shl rdx, 32
89 c0                 mov eax, eax
48 09 c2              or rdx, rax             ; rdx = LSTAR
48 8d 8a 40 fe ff ff  lea rcx, [rdx-0x1c0]
0f 20 c0              mov rax, cr0
48 25 ff ff fe ff     and rax, ~0x10000       ; clear CR0.WP
0f 22 c0              mov cr0, rax
...
66 89 81 <disp32>     mov [rcx+disp32], ax    ; <- the per-firmware address
```

This is the **"661 kexec shellcode / LDR (LSTAR) defeat"** stage from the chain playbook:
it reads the LSTAR MSR, disables write-protect, and patches the kernel from ring 0.

**The only per-firmware difference is the embedded `disp32`:**

| blob | embedded address |
|---|---|
| `1302.bin` | `0x1b76f3` |
| `1350.bin` | `0x1b7703` |
| **`1352.bin`** | **`0x1b77a3`** |

These are **the real 13.52 patch-site addresses**. In our dump at `0x1b77a3` we read
`90 90 90 90 90 90` (NOP padding) — again consistent with a layout offset difference
(§12.3), not with a wrong value. **Resolve the mapping, then these three addresses give you
the exact patch sites, which in turn localise the kernel code the chain touches.**

## 12.6 Existing reference dumps and working dumpers — we are not starting cold

Found on disk during this check. **Read/compare these before re-deriving anything:**

```
C:\Users\Kinan\Downloads\czdji0\1352k.elf        20,080,104 B  <- reference 13.52 (ELF, 6 phdrs)
C:\Users\Kinan\Downloads\czdji0\1350.elf         21,657,064 B
C:\Users\Kinan\Downloads\czdji0\1302.elf         21,657,064 B
C:\Users\Kinan\Downloads\czdji0\kernel1304.elf   21,657,064 B
C:\Users\Kinan\Downloads\czdji0\1150k.elf        20,080,096 B
C:\Users\Kinan\Downloads\WORKING-dumper-v6-canary-locked\ps-dump-v6.elf    55,284 B
C:\Users\Kinan\Downloads\WORKING-dumper-v7-dumper-locked\ps-dump-v7.elf    55,104 B
C:\Users\Kinan\Downloads\WORKING-dumper-v8-dumper-locked\ps-dump-v8.elf    55,076 B
C:\Users\Kinan\Downloads\WORKING-dumper-v9-canonical-locked\ps-dump-v9.elf 55,104 B
C:\Users\Kinan\Downloads\bd-j-usr\research\kerneldump_1352.bin              32 B  (stub)
```

Note `1302.elf`, `1350.elf` and `kernel1304.elf` are **byte-identical in size** — consistent
with `ps4_offsets.js`'s claim that 13.02 and 13.04 are the same kernel.

`1352k.elf` at `20,080,104 B` (`0x13265e8`) is the reference the chain's RVAs were measured
against. **Our `kmemfull.bin` (28,468,712 B) is larger and flat** — see §12.3.

## 12.7 New helper scripts added to this folder

| script | purpose |
|---|---|
| `verify_1352_offsets.py` | checks the authoritative 13.52 offsets against the dump |
| `resolve_base_and_extent.py` | base-convention and image-extent analysis |
| `decode_patch_blobs.py` | decodes the shellcode patch blobs |
| `cross_check_reference.py` | compares our dump against `1352k.elf` |
| `test_base_convention.py` | the refuted segment-relative hypothesis |
| `probe_bug_classes.py` | which bug-class surfaces are present as strings |

## 12.8 Revised immediate next actions

1. **Run the second dump pass** (§12.4) — `0x1b265e8..0x2400000`. Without it the chain's
   own offsets cannot be validated end to end.
2. **Establish the offset mapping** between the chain's RVAs, `czdji0\1352k.elf`, and
   `kmemfull.bin` (§12.3). Use ≥3 anchors. Everything else depends on this.
3. **Read `ps4_offsets.js` and `jb.js` in full** — `ps4_offsets.js` is the ground-truth
   offset table for every firmware from 11.00 to 13.52, including `fw_status` provenance
   notes that tell you what was hardware-proven vs asserted.
4. Then proceed to §7.
