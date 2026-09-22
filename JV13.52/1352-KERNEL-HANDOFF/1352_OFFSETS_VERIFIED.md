# 1352_OFFSETS_VERIFIED — chain offsets proven against kmemfull.bin

**Successor session, 2026-09-22.** This closes HANDOFF §12.8 item 2 (offset mapping)
and §7 Workstream A. It **supersedes §12.3's "+0x800000 shift" conclusion**, which was
an artefact.

## 1. THE MAPPING — identity, proven

**Chain RVA == kmemfull.bin file offset == VA − kbase, everywhere.**

Proof: our dump contains the kernel's own **live program headers** (e_phoff=0x40,
e_phnum=6 — HANDOFF §2's "e_phnum==0" was a field-offset bug in verify_kdump.py's
`unpack_from('<HHH', d, 0x36)`; correct fields are e_phentsize/e_phnum at 0x36/0x38):

```
[2] PT_LOAD  RX  file 0x0        <-> va kbase+0x0        fsz 0xcfe758   (.text: IDENTITY)
[3] Orbis-ext R  file 0xcff000   <-> va kbase+0x10ff000 fsz 0x20cc0     (sysent lives here)
[4] PT_LOAD  RW  file 0xd20000   <-> va kbase+0x1520000 fsz 0x6065e8    (.data; file=VA-0x800000)
                                    msz 0x1314af0                      (.data+bss -> VA 0x2834af0)
```

The reference 1352k.elf's ORBISYS at its file offset 0xd20000 is simply **its RW
segment p_offset** — the prior session compared ref *file offset* vs our *VA* and
manufactured a fake "+0x800000". Within the RW segment the correct conversion is
file = RVA − 0x800000; elsewhere (`.text`, Orbis ext) it is identity.

## 2. End-to-end verification of the 13.52 chain values

| symbol | RVA | verdict — evidence in kmemfull.bin |
|---|---|---|
| k_jmp_rsi | 0x4d6d0 | ✅ `ff 26` = **jmp [rsi]** (misaligned gadget; sy_call(td,args) → rsi=args → jumps to args[0] = user RWX). Name is loose, value correct. Blob cross-proof: writes LSTAR+0x4d510 here, LSTAR RVA=0x1c0 → 0x1c0+0x4d510=0x4d6d0. |
| LSTAR / Xfast_syscall | 0x1c0 | ✅ bytes at 0x1c0 = `0f 01 f8 65 48 89 24 25 a8 02...` = swapgs syscall entry. |
| k_sysent | 0x1102b70 | ✅ live sysent: {i32 narg, ptr sy_call} stride 0x30, sy_call = this-boot kbase pointers. |
| k_sysent_661 | 0x110a760 | ✅ narg=4, sy_call=kbase+0x11f6f0 — the KEXEC hijack target. |
| k_kl_lock | 0xe6c60 | ✅ real code prologue at 0xe6c60 (`55 48 89 e5 48 8d 15...`); ~0xe6c20 area also code — consistent with a lock-adjacent helper; usable for kbase derivation as the chain does. |
| k_evf_cv | 0x785228 | ✅ literal string "evf cv" — scan anchor. |
| k_sysctl_handle_int | 0x3fa8e0 | ✅ function prologue. |
| k_idt_rsvd | 0x1c1e00 | ✅ plausible (patch-site-adjacent region). |
| k_prison0 / k_oid_* | 0x1a5c0c0 / 0x1a2f8a0.. | ✅ in v11 dump (RW segment): oid entries hold kbase pointers (sysctl oid list). |
| k_rootvnode | 0x2136e90 | ✅ v11 reads `0xffffc187162a8000` — valid DMAP vnode pointer. |
| k_arg1_maxfiles* | 0x22cc474..7c | ✅ v11 reads plausible sysctl int values. |

## 3. The 1352.bin patch blob — 27 writes, ALL sites verified

Disassembled (capstone) from `raw13g.../patches/1352.bin` (632 B). It runs in ring0
via the sysent[661]→jmp[rsi] hijack: reads MSR_LSTAR, `rcx = LSTAR-0x1c0` (kbase),
clears CR0.WP, applies patches, restores WP, `xor eax,eax; ret`.

Sites (all land in the correct region with the expected pre-patch bytes in our dump):
.text: 0x490(d)=0, 0x4b5/0x4b9(w)=eb.., 0x4c2(b)=eb, 0xacd(b)=eb, 0x6283c4/0x628caf(w)=eb,
0x1b7264(w), 0x1b77a3/0x1b77b3(w)=eb04, 0x1b77d3(w)=e990, 0x1b7818(d), 0x2fc8ac(w)=eb04,
0x391d16(b)=eb, 0x3be110(d)=`48 31 c0 c3`, 0x1fa83a/0x1fa83d(b)=0x37, plus the
`0x2bd4ed/31/5ad/5f1/79d/c4d/d1d` `eb` stub family; sysent (Orbis ext):
0x1102d80(d)=2, 0x1102d88(q)=LSTAR+0x4d510 (=k_jmp_rsi), 0x1102dac(d)=1;
`0x125631..0x125711` = the in-.text "661 kexec" stub table the chain writes.

## 4. THE SECOND DUMP PASS ALREADY EXISTS

`../v11_kmem_img.bin` (20,007,664 B) is a live dump of kbase-rel
**0x1520000..0x2834af0** — the full RW memsz per phdr[4]. It covers the entire
§12.4 "missing" region (rootvnode, arg1_*, and beyond 0x2400000). Same firmware
(ORBISYS identical; 89.0% of overlapping 4 KiB blocks byte-identical — the delta is
KASLR pointers, v11 boot kbase=0xffffffff85680000 vs ours 0xffffffffc5530000).

**§12.4's second-pass payload run is therefore NOT required** for offset
validation; it is only needed if a same-boot image of 0x1b265e8.. is wanted
(non-static runtime state).

## 5. Known-chain bug identification (for the §7 B7 diff step)

The 13.52 chain is `bug=663` (per ps4_offsets.js fw_status) — a **syscall-663
(netcontrol?) based chain**, not Poops (`ip6_pktopts`, ≤12.52) and not lapse (12.02).
Any audit finding must be checked against bug-663's surface as the patched reference.
(The exact 663 primitive function should be located in the dump next: sy_call =
kbase+0x11f6f0 → .text 0x11f6f0 — wait, that's the pre-patch sysent[661] handler;
sysent[663] @ 0x110a7c0 is the real target to disassemble. TODO below.)

## 6. sysent[663] IDENTIFIED — `_aio_multi_wait` @ RVA 0x11ff50

The known chain's kernel bug entry (`bug=663` per ps4_offsets.js). Handler shape
(disassembly in successor session notes):

```
sysent[663] narg=5  sy_call=kbase+0x11ff50
0x11ff50  5-arg unpacker: args -> (rdi=td, rsi=arg0 ptr, edx=arg1 count, rcx=arg2,
           r8d=arg3, r9=arg4) -> tail into 0x11ff70 (real body)
body:
  - reads td->td_proc fields (+0xab8, +0xaf4) -> selects a per-proc aio context
    (stride 0x598 array, sel == 1 check, error path via priv-check-style call 0x1232d0)
  - arg1 (count) validated: (count-1) < 0x81  i.e. count in 1..0x81
  - arg3 >= 3 rejected (EINVAL path, line 0xfbf)
  - count >= 2 path:  alloca(count*4 + 15, 16-aligned) on KERNEL STACK
                      call 0x2bd4e0 (memset/memcpy family)
  - final: copyin(arg0, dest, count*4)   via 0x2bd790 ("copyin" str @0x7984fc)
  - errors print "%s() line=%d error=%d 0x%x" with __func__ "_aio_multi_wait"
    (string @0x797fbf) -> lines 0xfaf/0xfb5/0xfbf/0xfce
```

**This is the patched reference surface.** Per §7 B7: any audit finding in the
`aio_multi_*` family (there will be sibling syscalls — 662 `narg=3` unpacks 2 args
differently, 664/665/666 neighbours) must be diffed against this known-bug family
before being reported as new. The neighbouring syscalls and the copyin/alloca
helpers (0x2bd4e0, 0x2bd790) are the first places to look for *un*patched cousins.

### 7. aio_multi family audit (B7 diff base) — first results

Handler map (string-xref proven):
```
sysent[662] narg=3  0x11f710  _aio_multi_delete
sysent[663] narg=5  0x11ff50  _aio_multi_wait     <- the known bug=663
sysent[664] narg=3  0x120c50  _aio_multi_poll
sysent[665] narg=2  0x121130  _aio_multi_cancel + _aio_submit_cmd refs
sysent[666] narg=3  0x121150  _aio_multi_cancel + _aio_submit_cmd refs
sysent[669] narg=5  0x1219c0  _aio_submit_cmd
```

**Provenance discovered:** `_aio_multi_poll` @0x12100a references
`W:\Build\J02697906\sys\freebsd\sys\kern\vfs_aio2` — the family is Sony's
**vfs_aio2** (PS4-specific aio rework of FreeBSD's vfs_aio). Build id J02697906.
(Generalizes the HANDOFF §7-B1 symbol trick: assert paths name the source file.)

**Honest negative result (per §10.10):** all three multi_* handlers share an
identical prologue: `count` validated `(count-1) < 0x81` (i.e. 1..0x81),
then `alloca(count*4 + 15) & ~15` on the kernel stack, `copyin(arg0, dest,
count*4)` via 0x2bd790. Max 516 B — **the stack-length-bug hypothesis is dead.**
The handlers then loop over the copied ids (`id > 0x7fffff` filtered, low 16 bits
= aio id, high 16 = idx) and manipulate aio contexts through the per-proc table
(stride 0x598) with helpers 0x24e550 (lookup), 0x24e510 (release?), 0x24dd80,
mtx/assert helper 0x68fb0, logfn 0x2e0510, debug-state call 0x2459b0.

**Therefore bug=663 is most likely a race/UAF in the shared completion/lookup
logic** (0x24e550/0x24e510 paths) rather than a length error — and 14.00 = 13.52
+8 bytes is consistent with a tiny fix (e.g. a refcount/flag check). The race
surface between _aio_multi_wait (blocking) and _aio_multi_delete/_aio_multi_poll
operating on the same per-proc aio table (stride 0x598, sel at +0x4a0) is the
primary 0-day audit target this session bequeaths to Workstream B.

### 8. orbis_idt.c — the id→object layer (bug=663's true home)

The aio helpers are not aio code: they are Sony's **generic ID-table allocator**,
`W:\Build\J02697906\sys\freebsd\sys\kern\orbis_idt.c` (also used by helper
0x24dd90 and presumably many other Sony drivers — every subsystem with
"handle/id + generation" semantics).

`orbis_idt` lookup @ 0x24e550 (called from _aio_multi_delete/poll with the
32-bit user id split: idx = id & 0x1fff, gen = (id>>13)&0x1fff... actually
entry gen at +0x28 << 13 | idx compared to full id):

```
1. mtx_lock(table)                       [0x378a80: lock cmpxchg @+0x18]
2. idx bounds check vs table->count (+0x220)<<7
3. entry = table->buckets[..]; validate gen (entry+0x28<<13 | idx == id)
4. validate state word [entry+0x26] == 3
5. entry->owner(+0x18) = curthread  (marked "in use by me")
6. mtx_unlock + re-validate owner still == curthread (retry loop)
7. state re-check == 3; if entry->obj(+0x10) != NULL:
       *out = entry;  return entry->obj    <- POINTER RETURNED
8. mtx_unlock                            [0xa3950/0xa3a00 family]
```

**The TOCTOU window:** the object pointer is handed to the caller **after the
table lock is released**, and the caller (e.g. `_aio_multi_wait`, which *blocks*
on the returned aio ctx) uses it unlocked. A concurrent `_aio_multi_delete` on
the same id (different thread, same process — both unprivileged) can transition
the entry (state, generation bump, obj free) between steps 6-8 and the waiter's
subsequent dereference. Owner-check at +0x18 partially guards it, but the waiter
sleeps *while holding owner*, and delete paths must decide whether to
steal/free — that interplay is where a UAF would live, and where an 8-byte fix
(a flag/refcount) would produce exactly "14.00 = 13.52 + 8".

### 9. orbis_idt consumer map (xref-complete) — the 0-day target list

All call sites of the orbis_idt entry points, attributed by provenance-string
proximity (17,531 lea refs to `W:\Build\J02697906\...` strings used as the
attribution oracle):

| consumer file | entry points called | reachability | audit priority |
|---|---|---|---|
| `sys\freebsd\sys\kern\orbis_evf.c` | lookup/release (callers @0x6c78c..0x6ccc2) | **event-flag syscalls — unprivileged, any process** | **1** |
| `sys\freebsd\sys\kern\kern_dynlib.c` + `subr_dynlib.c` | release/lookup (@0x1b73c8..0x1b760c, 0x3b9887) | **sceKernelLoadModule family — unprivileged** | **1** |
| `sys\freebsd\sys\kern\vfs_aio2.c` | all (@0x11f987..0x123a22) | unprivileged (the KNOWN bug=663 home) | reference surface |
| `sys\freebsd\sys\kern\orbis_budget.c` | lookup (@0xa6520..0xa780a) | budget syscalls — likely unprivileged | 2 |
| `sys\dev\mem\memutil.c` | (@0x48a071..0x48a13f) | /dev/mem — check perms | 3 |
| `sys\internal\modules\sdbgp\`, `ipmimgr\`, `dev\usb\cam` | | internal/dev — low priority | 4 |

orbis_idt.c's own implementation block: 0x24dd80..0x24ef30 (25 functions;
lookup=0x24e550, release=0x24e510, insert/delete-family around 0x24dd90/0x24dea0/
0x24e440/0x24e480/0x24eb50; 0x24d820 = 67-caller mega-entry, likely id-alloc).

**Next-session audit procedure:** for each priority-1 consumer, replicate the §8
analysis — does the caller hold a reference across the entry's unlock, and can a
second unprivileged thread free/replace the object in that window? If orbis_evf
or kern_dynlib has the same shape as vfs_aio2's bug=663, that is a genuinely new
0-day with identical reachability — and by §5.3's "+8 bytes" reasoning, likely
still live in 14.00 unless Sony's fix covered the *generic* layer rather than
just the aio caller.
2. Widen `extract_symbols.py` over the whole image (label the 13.6 MB of .text).
3. rtsock / priv_check unprivileged-path check (§11) — rtsock strings at 0x7becb1+,
   priv_check 0x7a3574, `copyin` string anchor 0x7984fc now also known.
4. KASAN FreeBSD 9 oracle for candidates (§7 B5) — note vfs_aio2 is Sony-specific,
   so the FreeBSD 9 diff base only covers the stock portions, not this family.
5. Honest triage per §5.6/§10.10; reject anything not reproducible cold-boot.
