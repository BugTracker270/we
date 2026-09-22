# 13.52 AuthMgr — re-opened: the "missing key" conclusion is wrong

**Supersedes §10 of `1352-SBL-OFFSETS.md` ("EINVAL is a missing KEY, not a malformed packet").**

**Verdict: the goal is NOT impossible, and it was never demonstrated to be.**
The blocker the project believed in — "the EEKC key store is empty, so a SELF header
can never be verified, so no packet spelling can ever work" — does not survive contact
with the kernel image. Four independent pieces of evidence kill it, below.

All claims here were produced by re-reading the decrypted 13.52 kernel
(`czdji0/1352k.elf`) with **disassembly-independent** tooling, and by re-reading the
live 20 MB kernel dump (`v11_kmem_img.bin`, koff base 0x1520000). Nothing here is a
simulation.

---

## 1. The console verifies SELF headers perfectly well — with the key store empty

This is the decisive one. The live dump's `self_contexts[4]` array
(koff `0x0269C140`, stride 0x60) is **populated with real, completed verifications**:

| slot | format | total_header_size | header ptr (ctx+0x38) | ctx_id (ctx+0x1C) |
|---|---|---|---|---|
| 0 | 2 (SELF) | 0x780 | `0xffffff80054b8000` | **1** |
| 1 | 2 (SELF) | 0x750 | `0xffffc18715a6d000` | **2** |
| 2 | 2 (SELF) | 0x750 | `0xffffc18715a6e000` | **0** |
| 3 | 2 (SELF) | 0x750 | `0xffffc18715a6f000` | **3** |

`ctx_id` is written in exactly one place — `verifyHeader`, koff `0x64054A`:

```asm
64054A  mov  eax, dword ptr [rbp - 0x94]   ; packet+0x1C
640552  mov  dword ptr [r14 + 0x1c], eax   ; ctx->ctx_id = packet+0x1C
```

`packet+0x1C` is **output-only** — the kernel `bzero`s it and only reads it back. So a
non-zero, distinct `ctx_id` per slot means **the secure module replied and echoed an
auth context id four separate times on that boot.** Three of the four also carry a
distinct `total_header_size`, i.e. each slot processed a *different* SELF.

And on that same boot, in that same dump:

* `sm_flag` (`0x0269C098`) = **1**
* `module_id` (`0x0269C0A0`) = **0**
* EEKC root (`0x0269C300`) = **0**

So the module-handle global reading 0 is **not** a failure condition — it reads 0 on a
console that is demonstrably verifying SELF headers. §8.4's "red herring" was right for
the wrong reason; it is now proven rather than asserted.

**Consequence:** "SELF header verification cannot work on this machine" is false.
Whatever our payload is doing wrong, it is not a structural impossibility.

---

## 2. `verifyHeader` returns the *mailbox error* verbatim — so "EINVAL" was never unambiguous

`verifyHeader` (koff `0x6401F0`, log-name `verifyHeader`, file
`…\sbl\authmgr\authmgr_secure_module.c`) sends the packet like this:

```asm
640396  lea  r15, [rip + ...]   ; koff 0x269c0c8 = SM_XLOCK
6403b8  call sx_xlock
6403BD  mov  rdi, qword ptr [rip + ...]  ; koff 0x269c0a0  <-- mailbox destination
6403C4  lea  rdx, [rbp - 0xb0]           ; reply
6403CB  mov  rsi, rdx                    ; query
6403CE  call sceSblServiceMailbox        ; koff 0x630230
6403DE  mov  ebx, eax
6403E0  call sx_xunlock
6403E5  test ebx, ebx
6403E7  je   0x64040A                    ; ok -> read packet+0x04 as the module verdict
6403E9  ...  log "ERROR: %s(%d) mailbox err%08x"   (0xaed427 / %s = "verifyHeader")
640405  jmp  0x640603                    ; *** RETURN ebx (the mailbox error) ***
```

So the function has **two** failure channels returning the same register:
the mailbox's own error, and `packet+0x04` (the module's status). Run 4's
`verify = 0xffffffffffffffea` was read as "the secure module said EINVAL". It could
equally have been "the mailbox call failed with EINVAL", and **nothing in the
project ever separated those two cases.**

---

## 3. The EEKC store *can* be written — it is an RB-tree with a real insert path

§10.1 concluded the store is a singly-linked list whose only writer is a
clear-to-zero. Both halves are wrong.

### 3.1 Naming (from the kernel's own log strings)

| koff | name | evidence |
|---|---|---|
| `0x643FB0` | `authmgr_ioctl` | `"ERROR: %s(%d) ..."` with `%s` = `authmgr_ioctl` @ `0xaedf34` |
| `0x644D70` | `sceSblAuthMgrAddEEkc3` | `"ERROR: %s(%d) sceSblAuthMgrAddEEkc3 0x%08x"` @ `0xaedf08` |
| `0x6454F0` | `sceSblAuthMgrAddEEkc2` | @ `0xaedf9b` |
| `0x6452A0` | `sceSblAuthMgrAddEEkc` | @ `0xaedf70` |
| `0x644FD0` | `sceSblAuthMgrDeleteEEkc` | @ `0xaedf42` |
| `0x645110` | EEKC lookup | walks root `0x0269C300` |
| `0x645250` | EEKC init | `sx_init(0x0269C2E0, "s_EEKcMgrCtx")` (`0xA35C0`) then `mov [0x269C300],0` |
| `0x645280` | EEKC fini | tail-call `0xA3640` (`sx_destroy`) on `0x0269C2E0` |

`%s` in those messages is `"authmgr_ioctl"` because the ioctl layer logs first:

```asm
643FBA  mov ecx, 0xc04c4102
643FC7  cmp rsi, rcx
643FCA  jg  0x64402C
643FCC  mov ecx, 0xc0484101
643FD4  je  0x644095          ; -> 0x6452A0   AddEEkc
643FDA  mov ecx, 0xc0484102
643FE2  jne 0x644127          ; default: eax = 0xfffffffd
643FE8  ...
644002  call 0x644fd0         ; DeleteEEkc
...
64402C  cmp rsi, 0xc04c4103
644034  je  0x6440D2          ; -> 0x6454F0   AddEEkc2
64403A  cmp rsi, 0xc0504104
644042  jne 0x644127
644062  mov edx, dword ptr [r14 + 0x44]    ; key_id
644066  mov ecx, dword ptr [r14 + 0x48]    ; aux
64406A  lea rsi, [r14 + 0x24]              ; the 0x20-byte value
64406E  mov rdi, r14
644071  call 0x644d70                      ; *** AddEEkc3 (insert) ***
```

So the request struct is `{…, value @ +0x24 (0x20 B), key_id @ +0x44, aux @ +0x48}`
and each sub-command writes its status back over `[r14+0x44/0x48/0x4c/0x50]`.

**`0x644D70` is reached from exactly one call site in the whole image: `0x644071`.**

### 3.2 The tree, and the write that the old scan could not see

`0x644D70` = allocate a `0x68`-byte node, fill `digest @ +0`, `value @ +0x20`,
`key_id @ +0x40`, `aux @ +0x44`, `flag @ +0x60`, then:

```asm
644F60  lea  rbx, [rip + ...]    ; koff 0x269c300   -> &tree root
644F67  jmp  0x644F6D
644F69  add  rbx, 0x48           ; else: &parent->left
644F5A  add  rbx, 0x50           ; else: &parent->right
644F6D  lea  rdi, [rip + ...]    ; koff 0x269c300
644F74  mov  rsi, r14
644F77  mov  qword ptr [rbx], r14   ; *** THE INSERT ***
644F7A  call 0x644440               ; tree insert-fixup / rebalance
644F7F  ...  sx_xunlock(0x0269C2E0)
```

and the traversal uses `add rbx,0x48` / `add rbx,0x50` with a sign test on the
`memcmp` result (`0x6451C9 js` / `0x6451CB je` / `0x6451CD add rbx,0x50`) — a **binary
search tree with children at `+0x48` (left) and `+0x50` (right)**, node size `0x68`.
`0x644D40` is the child-select helper (`mov rcx,[rax + rcx*8 + 0x48]` with `rcx` from
`setns`). There is no `next` at `+0x48`. The node layout in §10.1 is wrong, which
matters: **the hand-walk that softlocked the console was following `+0x48` as if it
were `next`, and `+0x48` is really the left-child pointer.**

### 3.3 Why the old scan missed the write

`xref_koff.py` / the §17 writer scan only classify **RIP-relative** operands. The
insert writes through a *register* (`mov qword ptr [rbx], r14`), so it is invisible to
that method while the clear at `645269` (`mov qword [rip+0x269c300], 0`) is not. That
asymmetry produced the false conclusion "the only write is a zeroing".

`recd.py` / `recd_all.py` (written this session, recursive descent — no desync, follows
real control flow) do not have that blind spot.

---

## 4. Both public references send **no key** for VERIFY_HEADER — and expect success

* `orbital-ref/tools/dumper/source/self_decrypter.c` (§`self_kverify_header`):
  `args->key_id = 0; memset(&args->key, 0, SELF_KEY_SIZE);` then
  `kassert(!ret); kassert(!args->status);`
* `ps5-selfdec-ref`: `struct sbl_authmgr_verify_header` has **no key field at all** —
  `{function, res, self_header_pa, self_header_size, unk14[8], service_id @0x1C,
  auth_id @0x20, unk28[0x10], unk38}` — and `_sceSblAuthMgrVerifyHeader()` returns
  `verify.service_id`, i.e. it reads `packet+0x1C` back. Same as our kernel.

The PS5 reference does **not** start the module either; it reads the handle out of
kernel memory (`offsets.offset_authmgr_handle`) — exactly the 13.52 global at
`0x0269C0A0`.

So a zero-key packet is the *normal, working* packet shape. The key fields are an
override for key types the module does not hold internally, not a precondition.

---

## 5. Run 7 measured nothing

`sdcfg` for run 7 was `maxstep=7 lock=1 svcreq=0 seg=0 ctxidx=0 smcall=0`, and step 7
returns early when `smcall==0`:

```c
o->rd[8] = a->smcall;
o->rd[9] = 0;
if (!a->smcall) { o->rc = 7; return; }
```

`g_r` (`struct sd_res`) is a **static**, and only `o->step` / `o->rc` are reset per
kexec — `rd[]` is *not* cleared. So in run 7:

```
verify=3  ctxid_out=3  ctx20=3      <-- rd[1], rd[2], rd[3]
```

are simply **`ctx_status[0..2]` left over from step 6**, not a module verdict:

```c
/* step 6 */ for (i = 0; i < CTX_COUNT; i++) { o->rd[i] = st[i]; ... }
```

`rcs=0,0,0,0,0,0,7` is consistent with that: steps 1–6 fine, step 7 bailing *by design*.
**No run has yet produced a trustworthy `verify=` value for the current payload.**

---

## 6. What is still genuinely unknown

The one thing not yet settled is **how the console's own path differs from ours**.
Both build the same packet; the console's succeeds four times per boot.

The best lead in the dump: the four good contexts carry `ctx->0x10` = a kernel-heap VA
and `ctx->0x38` = a heap page (`0xffffc18715a6c000 … a6f000`, four *consecutive* pages),
whereas our step 7 hand-writes `ctx->0x00/0x08/0x1C/0x20/0x28/0x30/0x38` and lets
`verifyHeader` derive `packet+0x08` as `*(0x269C0B8) + ctx->0x30 * 0x1000`.

**Conclusion: stop hand-populating the slot.** The console's `AuthHeader`
(koff `0x642B10`, file `authmgr.c`) is the real thing — it pulls the header in through
a caller-supplied read callback (indirect `call r13` at `0x6430F5`), copies it to
`ctx->0x38` (`0x6430E0`), then calls `0x63D100` = `call SmStart; jmp verifyHeader`
(`0x6431A6`). Using it removes every guessed field at once.

`SmStart` being called on that path is **safe and in fact a no-op here**: the flag
`0x0269C098` is 1, and `_sceSblAuthMgrSmStart` (`0x63E470`) branches straight past the
start call when it is:

```asm
63E4A3  cmp  byte ptr [rip + ...], 0   ; koff 0x269C098
63E4AA  jne  0x63E4F2                  ; already started -> unlock, ret (writes nothing)
```

This also retires the old SAFETY MODEL rule "never call `0x63E470`". With the flag set
it is provably just `sx_xlock` / `sx_xunlock`. (It is only a *first* start that is
risk-bearing — and on that path it is the console's own code doing it, not us.)

---

## 7. New symbols recovered this session (13.52, koff)

| koff | identity | note |
|---|---|---|
| `0x6401F0` | `verifyHeader` | `authmgr_secure_module.c`; returns mailbox err **or** `packet+0x04`; success writes `ctx->0x1C` from `packet+0x1C` |
| `0x63D100` | `_sceSblAuthMgrSmVerifyHeader` | literally `call SmStart; jmp verifyHeader` |
| `0x63E470` | `_sceSblAuthMgrSmStart` | flag-guarded; sets `0x269C098=1`; handle out via `sub_6300E0` arg6 → `0x269C0A0`; then `0x645830(handle)` |
| `0x63E580` | SM stop/reset | `sx_xlock(SM_XLOCK); byte [0x269C098] = 0; sx_xunlock`; only caller `0x643C56` |
| `0x645830` | post-start command `0x300` | packet `[0]=0x300`, `[8]=*(0x269C308)`; mailbox to the handle |
| `0x642880` | `authMgrPrologue` | `authmgr.c`; context acquire (rejects unless `ctx_status[c]+1 > 3`) then `0x63D0A0` |
| `0x642830/840/850/860/870` | thin wrappers | tail-jmp to `0x63E5D0 / 0x63E7A0 / 0x63E980 / 0x63EA50 / 0x641990` |
| `0x63E5D0` | staging-page setup | `kmalloc(0x4000, M_AUTHMGR)`, `mappages`, packet `[0]=0x402` |
| `0x63D0A0` | `IsLoadable`-ish tail | calls `0x63FFF0`, then `0x62DF80` and requires the version `>= 0x13520002`, else returns `0xffffffd2` (-46); then `memset(out,0,0x88)` |
| `0x642B10` | `sceSblAuthMgrAuthHeader` | header via read callback → `ctx->0x38`; then `0x63D100`; on success requires `ctx->format == 2` (else `-22`), sets `*out = header + num_entries*0x20 + 0x20`, releases the slot (`ctx_status 1 -> 3`) |
| `0x644D70` | `sceSblAuthMgrAddEEkc3` | RB-tree insert, node `0x68`, fixup `0x644440` |
| `0x644440` | tree insert-fixup | |
| `0x63CCC0` / `0x63CE60` | digest produce / validate | |
| `0x641840` | status-(-36) handler | called from `verifyHeader` when `packet+0x04 == 0xffffffdc` |
| `0x63D780` | digest resolver | still returns -2 for all nine SELFs on hand; no longer believed to gate success |

Note `verifyHeader`'s own `[4]`-entry `ctx_status` semantic: **3 = free**, acquire makes
it 4 (`0x642906`..`0x642914`), release sets it back to 3 (`0x643245`).

---

## 8. Corrections to the record (do not re-derive these)

1. §10's headline is wrong: the module was **not** rejecting a keyless packet. Keyless
   is the reference behaviour.
2. §10.1's node layout is wrong: **tree**, children `+0x48`/`+0x50`, node `0x68`.
3. The "only write to `0x0269C300` is a clear" claim is an artefact of RIP-relative
   scanning. `0x644F77` writes the root (and `+0x48`/`+0x50` children) via a register.
4. Run 4's `-22` is **ambiguous** (mailbox error vs module status); run 7's `verify=3`
   is **stale data**. There is no clean measurement of the SM verdict anywhere yet.
5. `brute_63d780.py` remains inconclusive and should stay retired.

## 9. What NOT to change

Everything in the existing SAFETY MODEL still holds, and one rule is *strengthened*:
never chase a pointer you have not validated. The new insert path was found by reading
code, not by walking memory — that is the method that works here. In particular, do
**not** hand-walk `0x0269C300` in the payload; if the store ever needs reading, ask
`0x645110` (it holds the lock and validates the walk) — and note that the child
pointers are a *tree*, so a "list walk" is structurally the wrong traversal.

---

# 10. Update — payload patched, and §6's recommendation amended

## 10.1 `self_context_t` read out field-by-field (settles an ambiguity)

`probe_ctx.py` prints the four live slots at 8-byte granularity instead of asking
anyone to eyeball hex. Result (koff `0x0269C140`, stride `0x60`):

| off | meaning | slot 0 | slot 1 | slot 2 | slot 3 |
|---|---|---|---|---|---|
| `0x00` | `u32 format` | 2 | 2 | 2 | 2 |
| `0x04` | `u32 elf_auth_type` | 0 | 0 | 0 | 0 |
| `0x08` | `u32 total_header_size` | 0x780 | 0x750 | 0x750 | 0x750 |
| `0x10` | `u64` | `0xffffff80054b8000` | heap VA | heap VA | heap VA |
| `0x18` | `u32` | 1 | 1 | 1 | 1 |
| `0x1C` | `u32 ctx_id` | **1** | **2** | **0** | **3** |
| `0x20` | `u64` | 0 | 0 | 0 | 0 |
| `0x28` | `u32` | 0x896487 | 0x40c72 | 0xa8f4 | 0xef79b |
| `0x30` | `u32 buf_id` | **0** | **1** | **2** | **3** |
| `0x38` | `u64 header ptr` | `…15a6c000` | `…15a6d000` | `…15a6e000` | `…15a6f000` |
| `0x40` | `sx` (mtx) | `0xffffffff8616ddda` | same | same | same |
| `0x48` | | 0x0000000001030000 | same | same | same |
| `0x58` | | 4 | 4 | 4 | 4 |

So **`ctx->0x30` is `buf_id`** — the `0x896487` that reads like a buf_id in the raw
hex is actually `ctx->0x28`. That matters: `verifyHeader` computes
`packet+0x08 = *(0x269C0B8) + ctx->0x30 * 0x1000`, and with `buf_id` = 0..3 the
console's own four header PA values are exactly `0xA56C000`, `0xA56D000`,
`0xA56E000`, `0xA56F000` — four consecutive pages. The payload's derivation was
right.

## 10.2 Those four contexts are SELFs we do not hold

`self_hdrs.py` over every SELF on hand:

| file | header_size | metadata | **hdrsz+meta** | entries |
|---|---|---|---|---|
| `80010001.self` | 0x120 | 0x1d0 | 0x2f0 | 2 |
| `80010002.self` | 0x100 | 0x1b0 | 0x2b0 | 1 |
| `80010006.self` | 0x160 | 0x240 | 0x3a0 | 3 |
| `80010008.self` | 0x160 | 0x280 | **0x3e0** | 3 |
| `80010009.self` | 0x160 | 0x260 | 0x3c0 | 3 |
| `8001000A.self` | 0x160 | 0x240 | 0x3a0 | 3 |
| `8001000B.self` | 0x160 | 0x240 | 0x3a0 | 3 |
| `80010002_kernel_14.00.self` | 0x100 | 0x1b0 | 0x2b0 | 1 |
| `orbis_swu.self` | 0x240 | 0x270 | 0x4b0 | 4 |

None is 0x750 or 0x780. So the four `total_header_size` values in the dump belong to
**modules we have no copy of** — which is why they cannot be matched against our
targets and why "our 0x3e0 must be wrong" is *not* a supportable inference. Our
0x3e0 for `80010008` is the value the header itself declares.

## 10.3 `AuthHeader` is NOT a drop-in — §6 amended

§6 proposed calling `sceSblAuthMgrAuthHeader` instead of hand-populating the slot.
Now that its entry is known, that advice is **withdrawn as written**:

* entry is **`0x642C90`** (not `0x642B10`; `0x642B10` is a small `u32`->`u32` error-code
  translator with two jump tables);
* it takes **8 arguments** (validates `rdi`, `rdx`, `r9`, `[rbp+0x10]`, `[rbp+0x18]` all
  non-NULL before doing anything);
* it looks for a slot with **`ctx_status[slot] == 0`** (`0x642D3D`–`0x642D64`) and returns
  `-16` if all four are non-zero — and on a booted console all four are **3**.

So calling it naively on this console returns `-16` without doing anything. Using it
would require first driving `ctx_status` into the state it wants — a guessed state
change, which is exactly the class of assumption that caused the first softlock. Not
doing that.

## 10.4 `sceSblServiceMailbox` sharpens §2

`0x630230` builds a 0x28-byte request header `{+0x00 = 9, +0x08 = 0, +0x10 = 0,
+0x18 = 0, +0x20 = module_id}` and copies **the caller's 0x80-byte packet into the
request body** (`0x630295`), submits via `0x631630`, and:

* returns `0` on success, and only then copies the reply body back
  (`0x6302C5: memcpy(reply_out, body, 0x80)`);
* on failure returns the transport status from `[rbp-0xcc]` (`0x6302F7`–`0x630313`).

Consequence: **on a mailbox failure the caller's packet is never written back**, so
`packet+0x04` stays 0. So `verifyHeader` cannot return a non-zero value from
`packet+0x04` unless the mailbox *succeeded*. That finally makes the two channels
separable — see 10.5.

## 10.5 What was changed in the payload this session

Three edits to `selfdec2/source/main.c`. Build is clean (`-Wall`, no warnings),
`selfdec2.bin` 27548 → **27580 bytes**.

1. **`memset(o->rd, 0, sizeof(o->rd))` in `sd_step`** (`:273`). `g_r` is a static and
   each step is a separate kexec, so `rd[]` inherited the previous step's values. This
   is the exact bug that produced run 7's bogus `verify=3 ctxid_out=3 ctx20=3` (which
   were step 6's `ctx_status[0..2]`). From now on a non-zero `rd[]` slot that we did
   not deliberately write is a bug, not data.

2. **`rd[9] = finalize(ctx)`** (`:559`) — a free transport probe.
   `_sceSblAuthMgrSmFinalize` (`0x63FF00`) sends AuthMgr cmd 5 through
   `sceSblServiceMailbox(*(0x269C0A0), q, q)` and **returns 5, not the mailbox error,
   when that call fails** (`0x63FFB4`), else 0 (`0x63FFCA`). The payload already made
   this call and discarded the result. So now:

   * `rd[9] == 0` → the mailbox works, and any non-zero `verify` is the secure
     module's **own** verdict on our header;
   * `rd[9] == 5` → the mailbox call itself failed and no packet content could ever
     have mattered.

   This is the single value that §2 said was missing, and it costs nothing.

3. **`uint64_t r = 0`** (`:259`). Step 4 only publishes a BUS address and then runs
   `if (r) o->rc = 4;` — a vestigial check from steps 5+. `r` was uninitialised, so a
   garbage stack value could abort the sequence and be reported as "step 4 failed"
   while nothing was wrong. This removes both the latent abort and the `-Wmaybe-uninitialized`
   warning.

Comments that encoded the disproven theory were corrected in place: the key-store
block (tree, not list; writable via `AddEEkc3`), the staging-page block (withdrawn
EINVAL attribution; `ctx->0x30 == buf_id` confirmed), and the SAFETY MODEL
`SmStart` bullet (rule kept, reason corrected).

## 10.6 The one open question, now sharply posed

Nothing further can be concluded from the image. The next run's report line
`rd[9]` decides between two very different worlds:

* **`rd[9] == 5`** → the AuthMgr mailbox path has never worked for this payload, and
  every "EINVAL" in the project's history is a transport artefact. The entire
  key-store / header argument is moot, and the next step is to find out why
  `sceSblServiceMailbox` fails from our thread.
* **`rd[9] == 0` and `verify == 0xffffffea`** → the transport is fine and the secure
  module is genuinely rejecting our header. Then the field to vary is the one the
  console's own path sets differently, i.e. `ctx->0x10` / `ctx->0x18` / `ctx->0x28`
  (all three are populated in the four live contexts and all three are written as 0
  by step 7 today), and `total_header_size`.

Either way the ambiguity that produced the wrong conclusion is now instrumented.

---

# 11. Run log — staging attempt for the transport probe (aborted before trigger)

**Payload was never executed.** The console went off the network during staging,
before BinLoader was touched, so nothing here is a payload crash and `rd[9]` has
still not been read.

What happened, in order:

| step | result |
|---|---|
| `check_alive.py` | console ALIVE (kernel still scheduling, log stream live) |
| FTP `STOR /data/payloads/sd.cfg` (50 B) | **OK** |
| FTP `STOR /data/payloads/target.self` (88,304 B) | **OK** (`SIZE` unreported) |
| FTP `STOR /data/payloads/selfdec2.bin` | refused, then timed out ×4 |
| FTP `STOR /data/GoldHEN/payloads/selfdec2.bin` | timed out ×4 |
| probe 2121 / 9090 / 3232 / 9026 | **all closed** |
| `ping 172.20.10.3` | *Destination host unreachable* |
| subnet sweep | only `172.20.10.1` (hotspot), `.2`, `.7` (this host) respond |

So `sd.cfg` (with `smcall=1`) and `target.self` are staged; the payload upload did
not complete, and the console left the hotspot.

Two candidate causes, neither confirmed:

1. The 88 KB FTP write — this project has killed GoldHEN's FTP server this way
   before, though that has previously degraded FTP only, not the whole stack.
2. Idle/suspend. The log stream had just shown
   `[SceSystemStateMgr] No user input for 900 seconds` and
   `UI system timer elapsed 00:41:00`, i.e. the console was ~41 min idle. A PS4
   suspended or Wi-Fi-sleeping drops off the network exactly like this.

**Recovery plan (and what to change next time):**
1. Power-cycle / wake the console and re-run GoldHEN, then confirm `2121` and
   `3232` respond.
2. **Re-stage without any large FTP write.** The two `selfdec2.bin` uploads are
   redundant: BinLoader *streams* the payload to 9090, so the `/data` copies are
   only there for the on-console payload menu. Dropping them removes the most
   likely trigger.
3. `target.self` is also 88 KB for something step 7 does not need: the payload only
   copies the **first 0x1000 bytes** into the BUF_B page, and `hdr_len` is only
   `0x3E0`. Check whether the userspace parse validates `self_size` against the
   header's declared `file_size` — if it does not, a 4 KB truncated target is
   enough for a step-7 run and cuts the FTP write by 95%.
4. On the console, disable auto-suspend / enable "Stay Connected to the Internet"
   so a long idle does not take the console off the hotspot mid-session.

`sd.cfg` currently on the console:
```
maxstep=7
lock=1
svcreq=0
seg=0
ctxidx=0
smcall=1
```

---

# 12. Run log — second attempt: GoldHEN died again, before the trigger

Console came back (power cycle + GoldHEN re-run). Timeline:

| probe | result |
|---|---|
| ports 2121 / 9090 / 3232 | **all OPEN** |
| `verify_stage.py` (1 connection, TYPE I + SIZE) | connected, then **EOFError on the first SIZE and on RETR** |
| `trigger_watch.py` (needs 3232 + 9090) | `ConnectionRefusedError` on **both** |
| `ping 172.20.10.3` | **responds** |
| ports 2121 / 9090 / 3232 / 9026 / 1337 | **all closed** |

So the console is up and on the network, but **GoldHEN has exited** — it provides
2121, 9090 and 3232, and it took all three with it. That FTP `EOFError` was not a
transient hiccup; it was GoldHEN dying, and by the time the payload was sent there
was nothing left listening.

Nothing was executed: the BinLoader send was refused, so `rd[9]` is *still* unread.

## 12.1 Two operational lessons

1. **Never probe 9090 by connecting and closing.** BinLoader is a one-shot
   listener, and `check_alive`-style port sweeps open-and-close it. `submit_payload.py`
   does a probe connect before its real send (step 1 then step 2) and
   `wait_goldhen.py` deliberately "never touches 9090". The payload send must be the
   **first** time 9090 is touched in a session.
2. **FTP staging is what keeps taking GoldHEN down.** Across two attempts, the death
   followed FTP writes (88 KB `target.self` the first time; a SIZE/RETR the second).
   Treat every FTP byte as expensive, and prefer zero or one small write.

## 12.2 Low-risk plan for the next attempt

Now ready so that no large write is ever needed again:

* `target4k.self` — the first 4096 bytes of `80010008.self`, created locally.
  Justification, all from `main.c`: the userspace parse rejects only
  `self_size < 0x100` (`:893`), takes `hdr_len` from inside the header (`:901`), and
  the `seg_off + seg_size > self_size` test (`:916`) merely zeroes `seg_size`, which
  only affects step 8 — and `maxstep=7` never reaches step 8. Step 7 itself copies
  exactly `PAGE_SZ` = 0x1000 bytes (`:460`), so a 0x1000-byte file is sufficient and
  in-bounds. This cuts the one dangerous upload by 95%.

Sequence:
1. Confirm 2121 and 3232 are open (`wait_goldhen.py`), checking 2121 and 3232 only.
2. **One** FTP connection: `SIZE /data/payloads/target.self`.
   * 88304 → already intact, do nothing else.
   * absent or wrong → upload `target4k.self` (4 KB) to `/data/payloads/target.self`.
3. Only if needed, write `/data/payloads/sd.cfg` (50 B) — `smcall` defaults to 0
   (`:758`), so without it step 7 returns early and there is no probe at all.
4. Collect the outcome from the **3232 log stream**, connected *before* the send
   (printf_notification output; `sd_status.txt` retrieval is optional). Data survives
   on the console if FTP dies again.
5. Send `selfdec2.bin` to 9090 — the first and only touch of 9090.

Expected report line: `verify=` and `rd[9]`, per §10.5/§10.6.

---

# 13. FTP is off the critical path: the payload is now self-contained

## 13.1 GoldHEN's FTP dies on its *first data command* — reproducibly

Third attempt, cleanest evidence yet:

| | op 1 on a fresh connection | result |
|---|---|---|
| attempt 1 | `STOR /data/payloads/sd.cfg` (50 B) | OK |
| attempt 1 | `STOR /data/payloads/target.self` (88,304 B) | STOR returned, `SIZE` failed |
| attempt 1 | `STOR .../selfdec2.bin` | connection refused |
| attempt 2 | `TYPE I`, then `SIZE` | **EOFError** |
| attempt 3 | `TYPE I`, then `SIZE` | **EOFError** |

After each of those, 2121 **and** 9090 **and** 3232 are all refused while the console
still answers ping: GoldHEN has exited. So it is not the *size* of the write —
attempt 3 sent nothing at all, only a `SIZE`. It is the data command itself.

**Rule: never use GoldHEN's FTP for this work.** Every attempt to stage a file over
it has cost a GoldHEN restart.

## 13.2 The payload now needs nothing from the console's filesystem

Both staged inputs are gone from the critical path:

1. **`smcall` defaults to 1** in `sd_cfg_default` (`main.c`). Without this, `sd.cfg`
   *must* be placed via FTP (its absence leaves `smcall=0` and step 7 returns before
   the probe, making the run pointless). The old opt-out reasoning was also wrong —
   `sub_63D780`'s guard runs before the risky read and fails for this SELF, and the
   read address would be `header+0x140`, inside the page (see §10).
2. **The SELF header page is compiled in.** `gen_embed.py` emits the first 0x1000
   bytes of `80010008.self` as `selfdec2/source/embed_hdr.h` (`#include`d by
   `main.c`). If `target.self` is missing, `_main` falls back to
   `g_embed_hdr` / `EMBED_HDR_SIZE` and sets `self_embedded = 1`, which also guards
   the one `free(self)` site. Justification that 0x1000 bytes suffice is in §12.2:
   step 7 copies exactly `PAGE_SZ` and in-bounds.

These bytes come from an *encrypted* SELF already held locally — nothing secret is
embedded.

Verification of the new build:

* `selfdec2.bin` 27580 → **31724 B** (the +4144 is the embedded page plus rodata).
* SELF magic `4f 15 3d 1d` (i.e. `0x1d3d154f`) present at offset `0x69a0`.
* Build is clean, no warnings.
* In the report, `self=` will now read **4096**, not 88304 — that is the signal that
  the embedded path was used.

## 13.3 The next attempt is one TCP send

`fire_only.py`:
1. attaches to **3232** and uses it as the liveness check (so 2121 is never touched,
   and the capture is attached before the event — the stream is live-only);
2. sends `selfdec2.bin` to **9090** — the first and only touch of 9090;
3. reads `verify=` and `rd[9]` back out of the stream, and tries
   `RETR /data/payloads/sd_status.txt` only as a bonus.

No FTP write, no `sd.cfg`, no `target.self`. The only prerequisite is GoldHEN
running.

---

# 14. Run 8 — the payload executed. Four real results, and the blocker was self-inflicted

The payload ran. GoldHEN's own log proves the whole path works:

```
[GoldHEN] Klog server on port 3232
[GoldHEN] <payloader> Server started at 9090 port
[GoldHEN] <payloader> accepted a new payload
[GoldHEN] <payloader> payload received and saved
          [temp_file: /user/temp/payload.928525 - size: 31724 - ip: 172.20.10.7]
[GoldHEN] <payloader> found and jailbroken target process [proc: ScePartyDaemon - pid: 45]
[GoldHEN] <payloader> payload launched successfully
```

Full step trace, straight off the 3232 stream (`console_log_run8.txt`, 69,506 B):

```
selfdec2 kbase=ffffffff89214000
selfdec2 max=7 lock=1 svcreq=0 seg=0 ctx=0 sm=0
selfdec2 self=88304B hdr=992 seg0 off=13e0 sz=10f9c
step 1 rc=0 ffffff8009d64000 0 0
step 2 rc=0 0 189b8000 ffffc2832c212800
step 3 rc=0 ffffff8009d68000 0 0
step 4 rc=0 0 189bc000 ffffc2832c212800
step 5 rc=0 0 0 160
step 6 rc=0 3 3 3
step 7 rc=7 ffffc28305d4c000 0 0
```

## 14.1 `rd[]` fix confirmed

`rd[1]`/`rd[2]` now read **0** where run 7 printed stale `3`s. The cross-step
inheritance is gone, so anything non-zero in a future report is a real measurement.

## 14.2 Staging was never the problem

`self=88304B hdr=992 seg0 off=13e0 sz=10f9c` — **`target.self` is intact on the
console** at `/data/payloads/target.self`, from attempt 1. Nothing needed uploading,
and the embedded fallback went unused this run. `hdr=992` = 0x3E0 confirms the
header+metadata size we have been handing the module all along.

## 14.3 The blocker was `sm=0`, and it was ours

`sd_cfg_default()` was changed to `c->smcall = 1`, yet the run reported **`sm=0`**
and step 7 returned `rc=7` before the probe. So a stale `sd.cfg` won: almost
certainly `/mnt/usb0/sd.cfg` left from run 7 (which carries `smcall=0`), reached
because `/data/payloads/sd.cfg` is absent and `sd_cfg_parse` falls back to the stick.

That file cannot be corrected without FTP (13.1), so `_main` now forces
`c.smcall = 1` **after** the parse. The other keys stay honoured — run 8 shows the
correct `maxstep=7 lock=1 svcreq=0 seg=0 ctx=0`, and `svcreq=0` matters, since step 7
aborts before the mailbox whenever `svcreq && module_id == 0`.

## 14.4 The verdict was unreachable — now it is in the log

The detailed report (`verify=`, `rd[9]`) is written only to `sd_status.txt`, and
reading that requires FTP. So even a perfect run could not be read. The report is now
**also emitted to the kernel log**, line by line as `selfdec2 R: <line>`, which the
3232 stream carries. Retrieval no longer needs FTP at all.

Verified in the new binary: `selfdec2 R: ` marker present.

## 14.5 State after run 8

* Build: **32364 B**, sha256[:16] `7730F8B5AC826759`, clean, no warnings.
* `kbase` was `ffffffff89214000` this boot — KASLR moved it again, as expected.
* The payload only *reads* `ctx_status` (`:362`, `:496`); it never marks a slot busy,
  so nothing is left in a weird state on that account. It does overwrite
  `ctx->0x1C/0x30/0x38` in its chosen slot, which the kernel rewrites on its next
  real verify.
* The console dropped off the network again *after* the run completed. There is **no
  crash evidence**: the GoldHEN log ends on ordinary periodic `SceShellCore`/
  `SceSystemStateMgr` lines, with no panic, no GoldHEN error, and the payload
  reported `selfdec2: done`. Cause still unknown (idle/Wi-Fi are the standing
  candidates). This one is not attributable to the payload on current evidence.

The next fire is a single command and its report is now readable without FTP.

---

# 15. Run 9 — DECISIVE: the transport is fine, the module rejects the file

`sd.cfg` was finally bypassed (`sm=1` in the report) and step 7 issued the call.
Result, verbatim from the log:

```
selfdec2 max=7 lock=1 svcreq=0 seg=0 ctx=0 sm=1
ERROR: verifyHeader(1471) mail retval err -22
selfdec2 R: hdrptr=ffffa66705a6c000 verify=ffffffffffffffea ctxid_out=0 ctx20=0
selfdec2 R: bus=5a6c000 bufB=5a6c000 cbb=ffffa66705a6c000 smflag=1
selfdec2 R: digest=1 dptr=0 idx=0 copyin=0
selfdec2 R: ownbus=52ad0000 keyhead=0 smflag2=1 ctxstate=300000001
selfdec2 R: ctx=0 svc=0
```

## 15.1 The error is the module's verdict, not a transport artefact

Two independent proofs:

1. **The line number identifies the call site.** `0x64051E` is `mov edx, 0x5bf`, and
   `0x5BF = 1471` — exactly the `(1471)` in the message. That log call at `0x640510`
   is reachable only when `packet+0x04 != 0`, i.e. the mailbox **succeeded** and the
   module wrote a status. (The mailbox-failure branch is the *different* string
   `"mailbox err%08x"` at koff `0xaed427`, which we did **not** get.)
2. **`rd[9] = dptr = 0`.** `_sceSblAuthMgrSmFinalize` returns 5 when its own mailbox
   call fails and 0 otherwise; it returned 0. The transport works.

So: `verify = -22` is the secure module's own EINVAL, with `ctxid_out = 0` — it
assigned no context. **The five-run ambiguity is over.**

## 15.2 Our packet is provably identical to the console's

`AuthHeader` (`0x642C90`) derives the context fields itself, and this is its code:

```asm
642f2b  call memcmp              ; vs "\x7fELF"
642f36  je   0x642f6c            ; -> PLAIN ELF
642f44  call memcmp              ; vs 0x1d3d154f, the SELF magic
642f4d  je   0x642f8e            ; -> SELF
642f92  mov  dword ptr [r15], 2  ; ctx->0x00 = 2
642f99  movzx eax, word [rdi + 0xc]   ; header_size
642f9d  movzx r14d, word [rdi + 0xe]  ; metadata_size
642fa2  add  r14, rax                 ; hdr_len = header_size + metadata_size
642fb4  cmp  r14d, 0x1000
642fbb  ja   0x6430e8                ; reject with 0xffffffdd (-35) if > 0x1000
642fcb  mov  [rbx + rcx + 8], r14d    ; ctx->0x08 = hdr_len
642e74  mov  [rbx + r13 + 0x30], r12d ; ctx->0x30 = slot index
642e87  mov  [rbx + r13 + 0x38], rdi  ; ctx->0x38 = CTX_BUFBASE + slot*0x1000
642e62  call memset                   ; size 0x60: the context starts ZEROED
```

Comparing with `main.c` step 7:

| field | console's own path | our payload | |
|---|---|---|---|
| `+0x00` | 2 from the SELF magic | 2 | ✅ |
| `+0x08` | `header_size + metadata_size` | `hdr_len` = `0x3E0` | ✅ |
| `+0x30` | slot index | `idx` | ✅ |
| `+0x38` | `CTX_BUFBASE + slot*0x1000` | `page` (same expression) | ✅ |
| `+0x04` | 0 (memset) | 0 | ✅ |
| `+0x1C` | 0 (memset) | 0 | ✅ |

The `> 0x1000` guard is also satisfied (0x3E0). **Every field `verifyHeader` reads is
correct, and the values were derived the same way.** The packet is not the problem.

So the module has the right packet and still returns EINVAL on **this file**.

## 15.3 Two new side observations

* `ownbus=52ad0000` — our own mapped buffer's BUS this boot.
* **`ctxstate=300000001`** — `ctx_status[0] = 1`, `ctx_status[1] = 3`. Run 8 had
  `3,3,3`, so slot 0 became busy in between. Our payload only *reads* `ctx_status`
  (`:362`, `:496`) and never writes it, so this came from the console's own activity,
  not from us.
* `keyhead=0` — the EEKC store is still empty, as on every boot.

## 15.4 The experiment run 9 makes available

The log now also gives **real SELF paths this console loads**, which is the control
that has been missing. Straight from the 3232 capture:

```
# /app0/eboot.bin
# /app0/psm/Application/app.exe.sprx
# /app0/psm/Application/Sce.Vsh.EventApp.dll.sprx
# /siqKUaIVzd/common/lib/libkernel_sys.sprx
# /siqKUaIVzd/common/lib/libSceAudioOut.sprx
# /siqKUaIVzd/common/lib/libSceAjm.sprx          (… ~40 more in console_log_run8.txt)
```

`/app0/eboot.bin` is the strongest control available: the running application's own
SELF, which this console **has already loaded and verified**.

Next build: `_main` reads the first 0x1000 bytes of a handful of these paths (plus our
embedded `80010008` page as the known-good-or-not baseline) into separate buffers, and
step 7 loops: for each buffer, `copyin` → set `ctx+0x08` from *that* header's
`0x0C`/`0x0E` → `finalize` → `verify` → one log line per probe reporting
`index, hdr_len, verify, ctxid_out`. Logging the *read* result per path matters, so a
missing file is never mistaken for a rejected header.

That single run answers the real question: **does the module accept a SELF this console
verifiably loads, through our identical packet?**
* If yes → the packet/ctx path is proven, `80010008` is refused specifically, and the
  cause is then in the file (class, or an EEKC key its key_type needs).
* If no → our invocation is still wrong in a way the code reading has not exposed.

Note the paths from the log are as *one* process saw them, and our payload runs in
`ScePartyDaemon`; `/app0` may not resolve there. That is exactly why the read result is
logged per path instead of being assumed.

---

# 16. Runs 10-11 — a real bug found and fixed, and the console now dies every run

## 16.1 Run 10: two console SELFs are readable from our process

```
selfdec2 seek1 /app0/eboot.bin                        MISS
selfdec2 seek2 /app0/psm/Application/app.exe.sprx     MISS
selfdec2 seek3 /siqKUaIVzd/common/lib/libkernel_sys.sprx   MISS
selfdec2 seek4 /siqKUaIVzd/common/lib/libSceAudioOut.sprx  MISS
selfdec2 seek5 /system/common/lib/libkernel_sys.sprx  OK
selfdec2 seek6 /system/common/lib/libSceAudioOut.sprx OK
selfdec2 probe slots 7
```

`/app0` and the `/siqKUaIVzd` sandbox names come from another process's namespace and do
not resolve in `ScePartyDaemon` - predicted, and exactly why the read result is reported
rather than assumed. **The `/system/common/lib/` paths DO resolve**, so real console
SELFs are available to the probe and no FTP is needed to obtain them.

## 16.2 Run 10's actual defect: the probe list was wiped before the kexec

The run reported `verify=0`, `rc=7`, and **no `P<k>` line at all**. `rd[3]` — which the
new code sets to `a->n_hdr` — came back **0**. Cause:

```c
/* _main */
out_cap = ...            /* line 1138 - probe block runs around here, filling g_a */
...
memset(&g_a, 0, sizeof(g_a));   /* line 1144  <-- WIPES THE PROBE LIST */
g_a.kbase = kbase; ...
kexec(sd_step, (void *)&g_a);
```

So `n_hdr` was 7 when "probe slots 7" was printed and **0** by the time `sd_step` looked.
The loop ran zero iterations, which is why no per-slot line appeared and why `rd[1]`/`rd[3]`
were both 0.

Fixed by staging into file-scope `g_pb[8]`/`g_pn` (which the memset cannot reach) and
publishing into `g_a` immediately after the wipe. Verified: the newer builds carry both.

## 16.3 A second defect fixed in the same pass: format was hardcoded

Step 7 set `ctx+0x00 = 2` (SELF) unconditionally. But `AuthHeader` derives the format
from the **file's magic** (`0x642F2B` for `\x7fELF`, `0x642F44` for `0x1d3d154f`) and then
picks a different `hdr_len` expression for each:

* format 1 (plain ELF): `hdr_len = e_phnum*0x38 + 0x40` (`0x642F7B`, e_phnum = u16 at 0x38)
* format 2 (SELF): `hdr_len = header_size + metadata_size` (`0x642F99`)

A `.sprx` on this console may be a plain ELF, and hardcoding 2 would send the wrong
description for the file class - indistinguishable from a genuine refusal. The probe now
tests the magic itself and sets `ctx+0x00` and `hdr_len` accordingly, mirroring AuthHeader.
The per-probe line now reads:

```
selfdec2 P<k> fmt=<1|2> hdr=<len> verify=<status> ctxid=<id>
```

Build verified: **38572 B**, sha256[:16] `F2A6EA43E8C948E2`, clean.

## 16.4 The console now dies on every payload run - 4 for 4

| run | outcome |
|---|---|
| 8 | payload completed (`selfdec2: done`); console off the network after |
| 9 | payload completed; console off the network after |
| 10 | payload completed; GoldHEN down, console reachable, then down |
| 11 | **died during `_main`'s file reads**, before any kernel-mode step |

Run 11 matters: it stopped at `(_main:1138)` - the `seek3` line, mid-notification - with
only 792 bytes captured, having done nothing but announce itself and call `read_file`
twice. **No `sd_step` ever ran in that run**, so the ctx-slot writes, the mappings and the
verify/finalize calls cannot be the cause of that one. That points at the payload
*launch* path (GoldHEN hijacks `ScePartyDaemon` and kexec's into it - the log shows
`found and jailbroken target process [proc: ScePartyDaemon - pid: 46]`), not at our
kernel-memory work.

This also makes the earlier note about `[Syscore App] App Crash : PID=0x2b` worth
re-reading: a host-process crash would explain a whole-console failure if the hijacked
process is a system daemon.

**Recommendation: stop firing.** Four consecutive reboots have bought two facts and no
verdict. Before the next attempt, the payload should be made to leave no trace - at
minimum restore the `self_contexts` slot it overwrites (`+0x00/+0x08/+0x1C/+0x20/+0x28/
+0x30/+0x38`) instead of leaving fabricated values in a kernel structure the console
still uses - and the crash should be attributed before more runs are spent. The one thing
that is now certain is that the *result* of any future run is readable from the 3232 log
with no FTP, so a run that completes will not need another.

Nothing here is a dead end: the packet is proven correct (§15.2), the transport is proven
working (§15.1), two real console SELFs are readable without FTP (§16.1), and the probe
that discriminates "refused file" from "wrong invocation" is built and waiting.
