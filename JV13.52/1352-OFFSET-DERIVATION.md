
---

# 17. The prologue FOUND — `_sceSblAuthMgrSmStart`

## 17.1 Writer scan (widened opcode coverage)

The earlier ref scan only matched REX-prefixed instructions, so it missed
`cmp byte [rip+..]` / `c6 05 ..` / `80 3d ..` and friends. Redone with a full opcode
table over 13.6 MB: **82,114 RIP-relative references scanned, 191 land in the SM block.**

Writers found:

| koff written | sites | enclosing fn |
|---|---|---|
| `0x269C008`, `0x269C010`, `0x269C020` | `0x8283abc9`, `0x8283ac00`, `0x8283acf8`, `0x8283ad31`, `0x8283ad4d` | `0x8283ab50`, `0x8283ad10` |
| `0x269C028` | `0x8283c431`, `0x8283c47b`, `0x8283c5cc`, `0x8283c771`, `0x8283c7c2` | `0x8283c170` |
| `0x269C050`, `0x269C088`, `0x269C090` | `0x8283c23d`, `0x8283c8cd`, `0x8283cb3d` | `0x8283c170` |
| **`0x269C098`** (byte) | **`0x8283e4a3`, `0x8283e52f`** | **`0x8283e470` = SmStart** |
| `0x269C0A8` | `0x82840fbb` | `0x82840aa0` (SmLoadSelfBlock) |
| `0x269C108` (byte) | 7 sites, read-mostly (`cmp`/`test`) | all four public entry points |
| `0x269C0B0`, `0x269C0B8`, `0x269C0C0` | `0x82843ae8`, `0x82843b18`, `0x82843b2e` | `0x828434d0` (load) |

## 17.2 `_sceSblAuthMgrSmStart` @ koff `0x63E470` — the prologue

```asm
push rbp / mov rbp,rsp / push r14 / push rbx / sub rsp,0x10
lea  rbx, [rip+…]        -> koff 0x275CEA0                 ; stack canary
lea  rdi, [rip+…]        -> koff 0x269C0C8                 ; the SM mutex
lea  rdx, [rip+…]        -> "…\authmgr\authmgr_secure_module.c"
mov  ecx, 0xda                                             ; line 218
xor  esi, esi
call 0xffffffff822a3840                                    ; lock (same prim as smreq)
cmp  byte ptr [rip+…], 0 -> koff 0x269C098                 ; *** the START flag ***
jne  0x8283e4f2                                            ; already started -> skip
  lea  rdi, [rbp-0x1c]
  call 0xffffffff82834aa0                                  ; get an id into [rbp-0x1c]
  mov  esi, dword ptr [rbp-0x1c]
  lea  rdi, [rip+…]      -> "80010008"                     ; *** the AuthMgr module ***
  lea  r9,  [rip+…]      -> koff 0x269C0A0                 ; *** handle OUT (arg6) ***
  xor  edx, edx
  xor  ecx, ecx
  xor  r8d, r8d
  call 0xffffffff828300e0                                  ; start it
  test eax, eax
  je   0x8283e51c                                          ; success
  … error log "_sceSblAuthMgrSmStart" line 0xe7
```

### What this settles

1. **`koff 0x269C098` is the "SM started" byte flag.** It is 0 on our console, which is
   exactly why the §16 call faulted. `SmStart` is guarded on it and therefore **idempotent** —
   if it is already set, SmStart returns immediately.
2. **`koff 0x269C0A0` is the SM handle, and it is written by the start call** (`lea r9` →
   the address is passed as arg6, the callee writes the handle). The H-window in §13.2 showed
   `0` there — the handle had never been produced. This closes that loop exactly.
3. **The module being started is `"80010008"`** — the AuthMgr secure module. That is the same
   `80010008` our own audit notes reference for extracting SELF key banks from a decrypted
   AuthMgr. So this is unambiguously the right prologue.
4. **`SmStart` appears to take NO arguments**: every incoming argument register
   (`rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`) is *written* before it is ever read. (Worth
   confirming against its callers before relying on it.)

## 17.3 Revised plan

```
1. call _sceSblAuthMgrSmStart()          koff 0x63E470   <- NEW, 0 args, idempotent
2. re-read koff 0x269C098 (flag) and 0x269C0A0 (handle)  <- confirm the transport came up
3. call IsLoadable(etype, in, "/system_ex/", out)        <- §15
```

Step 1 is now the missing piece. Without it there is no transport, and every request path
dereferences NULL as observed.

## 17.4 Scanner bug worth recording

The first reference scanner only matched `48/4C 8D|8B|89 modrm`, i.e. REX-prefixed 64-bit
forms. It therefore silently missed `cmp byte [rip+..], imm8` (`80 3D`), `mov byte [rip+..], imm8`
(`C6 05`), `movzx` (`0F B6/B7`), `setcc`, `cmovcc` and all 32-bit forms. That is why
§16.5 reported "no references to the flag" — a false negative that sent the search the wrong
way for one round. Capstone linear disassembly also desynced after 12 instructions on this
image, so the deterministic byte-pattern scanner with a full opcode table is the tool of
record here.
