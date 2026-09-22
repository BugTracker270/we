# selfdec — PS4 13.52 SELF decrypter payload

**Status: built (`selfdec.bin`, 24,220 B) — not yet run on hardware.**

Decrypts a SELF container to a plaintext ELF by driving the console's **own** AuthMgr.
Built with the same `ps4-payload-sdk` toolchain as the working `ps4-pup-decrypt`
payload, so the build path is already proven on this console.

Every offset used here was recovered by static analysis of a decrypted 13.52 kernel
(`czdji0/1352k.elf`). Full evidence: [`../1352-OFFSET-DERIVATION.md`](../1352-OFFSET-DERIVATION.md).

---

## Layout

```
selfdec/
  Makefile                  same pattern as ps4-pup-decrypt
  build.sh                  docker build wrapper
  selfdec.bin               built payload
  include/
    offsets_1352.h          every derived offset, with provenance tags
    self.h                  SELF container structs + parser (orbital-derived)
  source/
    main.c                  probe + kernel worker + USB I/O
```

## Why two phases

The payload does **not** gamble on unverified signatures.

**PHASE 1 — probe (always runs, non-destructive).** Uses the SDK's
`get_memory_dump()` to read the derived addresses out of live kernel memory and print
what is actually there:

- `authmgr_handle @ kbase+0x0269C0A0` — expect a small integer (the value that logs as `4`)
- the 4-entry context table at `kbase+0x0269C140` — expect `idx` 0..3 at `+0x30`
  and a kernel pointer at `+0x38`
- the sm_service object base at `kbase+0x02681B80`

If those look right, the static analysis is confirmed on hardware and PHASE 2 is safe
to attempt. This is the run to do first.

**PHASE 2 — decrypt (opt-in).** `kexec()`s a kernel worker that calls the AuthMgr API
and writes `target.elf` to USB. It only runs if `/mnt/usb0/selfdec.mode` contains the
word `decrypt`. No mode file ⇒ PHASE 1 ONLY.

The worker records a **stage code** and the last return value it saw, so a failure tells
you *where* it stopped rather than just panicking:

| stage | meaning |
|---|---|
| 1 | SELF parse failed |
| 2 | `sceSblAuthMgrAuthHeader` failed |
| 3 | `sceSblAuthMgrLoadSegment/Block` failed |
| 4 | `sceSblAuthMgrFinalize` failed |

Expect panics during bring-up. The PS5 reference implementation is explicit that this is
normal ("the console may panic in the midst of dumping files, this is fine, restart the
console and run again"). On this console the JB is RAM-only, so a panic costs a reboot.

## Build

```sh
./build.sh              # or:
docker run --rm --entrypoint sh \
  -v "$PWD:/selfdec" -e PS4SDK=/lib/ps4-payload-sdk -w /selfdec \
  ps4-payload-sdk:latest -c "make clean && make"
```

Produces `selfdec.bin`. The `ps4-payload-sdk:latest` image already exists locally and
ships `libPS4.a`, so no image build is needed.

## Deploy

1. Copy `selfdec.bin` to USB.
2. Plug USB into the console (jailbroken 13.52, GoldHEN).
3. Launch the payload the same way `pup-decrypt-1352.bin` was launched.
4. Read the two on-screen notifications — that is PHASE 1's output.
5. Only after PHASE 1 reads correctly, create `/mnt/usb0/selfdec.mode` containing
   `decrypt` and put the target at `/mnt/usb0/target.self`.

Nothing here writes to flash. No step installs 14.00.

## Verified vs pending

| item | status |
|---|---|
| Kernel identity (1352) | ✅ verified |
| All derived offsets | ✅ from disassembly, see the derivation doc |
| AuthMgr context table layout | ✅ derived (`+0x30` idx, `+0x38` buf, `+0x40` mtx) |
| `sceSblServiceMailbox` address | ✅ located, 2 independent signals |
| `sceSblAuthMgrSmRequest` signature | ✅ derived from body + call site |
| AuthMgr API **addresses** | ✅ prologue-matched **and** confirmed call targets |
| AuthMgr API **argument layouts** | ⚠️ **PENDING** — typedefs are the orbital-derived best guess |
| `LoadSegment` vs `LoadBlock` split | ⚠️ **PENDING** — both resolve to `koff 0x006434d0` |

The two pending rows are exactly what PHASE 1 + the stage codes exist to resolve. They
are the only reason `decrypt_worker()` is written defensively rather than optimistically.

## The one thing no file on this disk can answer

Whether a 14.00 SELF keyset still matches what a 13.52 AuthMgr can decrypt. Everything
up to that point is now measured; that question is answered only by running it.
