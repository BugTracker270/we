# STAGE 1 — COMPLETE: 14.00 PUP decrypted, unpacked, kernel extracted

**Date:** 2026-09-20 · **Console:** PS4 13.52 + GoldHEN 2.2.0 (FTP 172.20.10.3) · **Kernel:** PS4 firmware was NOT touched

---

## 1. Headline

**It worked. The PUP is proven to be firmware 14.00, and the 14.00 kernel SELF is now extracted on this laptop.**

```
[14.00 PUP]                                        encrypted          <- we started here
      |
      |   console kernel encrypt service (/dev/pup_update0)          STAGE 1  ** DONE **
      v
[PS4UPDATE1.PUP.dec]  326,035,559 B   +   [PS4UPDATE2.PUP.dec]  177,294,015 B
      |
      |   pup-unpack.exe  (block tables -> decompression)
      v
[secure_modules.bin]  13,369,344 B  ->  SLB2, 7 modules
      |
      +-- 80010002  =  *** THE 14.00 KERNEL ***   10,867,186 B   <- extracted, still encrypted
      +-- 80010001  =  Secure Kernel                 98,676 B
      +-- 80010008  =  AuthMgr / Security Module     88,304 B    <- holds the SELF keys (Stage 2)
```

---

## 2. Proof that this really is 14.00

The firmware version lives in the SELF's `SceHeader.fw_version`, in the plaintext header region. To trust the decoder I validated it against a SELF whose firmware I already knew — **your console's own kernel**, pulled off its coreos device:

```
console's own kernel (13.52, known):  fw_version = 0x0000135200000000  ->  '1352'   OK
SELF inside the decrypted PUP:        fw_version = 0x0000140080000000  ->  '1400'   <- 14.00
```

Same decoder, same code path, correct answer on the known sample. **Your 480 MB file is firmware 14.00.**

Corroboration: the PUP contains **7 Secure Loaders (`80000001`)**, whose presence and per-hardware sizes are firmware-specific, and the `secure_modules.bin` module inventory matches a 14.00-class layout (7 modules, identical name set to the console's own coreos container).

---

## 3. The extracted kernel

**`dec/80010002_kernel_14.00.self`**

| field | value |
|---|---|
| size | 10,867,186 bytes |
| sha256 | `a0bff64e3611b70c2fdc26f6ea6e45ded9224f3469fea408a3dfd46e10668067` |
| magic | `4f 15 3d 1d` (SELF) |
| content_type / program_type | `0x01` / **`0x0C` = Kernel** |
| header_size / signature_size | `0x100` / `0x1B0` |
| SceHeader authority_id | `0x3C00000000000001` |
| SceHeader fw_version | `0x0000140080000000` → **`1400`** |
| segments | 1 |
| segment props | `0x00040F` → **signed=1, encrypted=1, compressed=1** |
| segment filesz → memsz | 10,866,430 → **21,652,976** (decrypted kernel ≈ 21.7 MB) |
| segment data (first 8) | `f5 4e 1e 4f a7 9a 70 d1` → **encrypted** |

So: the right binary, correct firmware, **still wrapped in the SELF layer** — exactly as predicted. Getting it to plaintext ELF is Stage 2/3.

---

## 4. Everything the decryption produced

`dec/PS4UPDATE1.PUP.dec` (326 MB) → `pup-unpack.exe` → **23 files**, notably:

| file | size | note |
|---|---|---|
| `system_fs_image.img` | 368,705,536 | **exFAT image** (`EB 76 90 "EXFAT"`) — mountable on Windows |
| `secure_modules.bin` | 13,369,344 | SLB2, 7 modules — **contains the kernel** |
| `dev/cd0` | 8,519,680 | SLB2, 6 entries `402R…420R` |
| `eap_fs_image.img` | 7,278,592 | `EB FE 90 "SCEI"` |
| `orbis_swu.self` | 3,175,511 | the updater (program_type 0x08, fw 1400) |
| `dev/da0x2` | 1,965,568 | |
| `eula.xml` | 1,021,350 | plaintext EULA |
| `torus2_firmware.bin`, `wlan_firmware.bin` | 524,288 ea | |
| `dev/sflash0s1.cryptx2b` | 253,952 | **Secure Loader (80000001)** |
| `dev/sflash0s0x32b` | 393,216 | EMC IPL |
| `dev/sflash0s0x33`, `dev/sflash0s0x38`, `dev/sc_fw_update0`, `dev/da0` | — | |
| `tables/*.img` | 7 files | block/compression tables per segment |
| `unknown/49.img`, `unknown/50.img` | 253,952 ea | |

`PS4UPDATE2.PUP.dec` (177,294,015 B) is also finished on the console — not yet pulled.

---

## 5. What was actually built to get here

Stock prebuilt payloads **cannot** do this: the only existing build (`andy-man` v0.1, 2024-04-07) predates 13.52 and froze your console in `jailbreak() -> kexec()` before any PUP code ran.

So I built one. **[pup-decrypt-1352.bin](pup-decrypt-1352.bin)** — 35,820 B, sha256 `e0ddcc37…512bf`:

- cloned `Scene-Collective/ps4-payload-sdk` (current main: firmware table holds `1352` **and** `1400`) + `andy-man/ps4-pup-decrypt`
- built the SDK toolchain image in Docker, compiled with the fixed payload
- **removed `jailbreak()`** (GoldHEN already provides the privileges; this call was the freeze)
- **moved the first notification to the top**, so any failure is visible text instead of a dead console
- added diagnostics: fw / uid / sandbox / `open("/dev/pup_update0")` + errno, with an `ABORT` notification instead of proceeding
- fixed a latent source bug: `decrypt.c` called `GetElapsed()` with no declaration; GCC ≥14 (current Ubuntu) rejects implicit declarations, which is why nobody had rebuilt this since 2024

Verified absent from the new binary: `Unsupported firmware` (the `build_kpayload` default arm) and `jailbreak` — the kexec path is gone at link time.

Observed on console: `PS4UPDATE1.PUP.dec` grew steadily at ~2.7 MB/s → 326,035,559 B exactly, then `PS4UPDATE2.PUP.dec` → 177,294,015 B.

---

## 6. Stage 2 — where the wall actually is

The kernel SELF's segment key/IV live in its **Segment Certification** block, protected by the SELF keys. Not in the file. To get them we need a **decrypted AuthMgr (`80010008`)** to run `80010008.py` against.

Current state of that:
- ✅ The **14.00** AuthMgr is now available to us — `80010008`, 88,304 B, inside `secure_modules.bin` — but **still encrypted** (same SELF layer).
- ✅ We also hold the 14.00 **Secure Loaders** (`80000001`, 7 variants) and the Secure Kernel — the whole key chain's inputs, from the PUP.
- ⚠️ Your console will not hand over its own decrypted secure modules (all 7 coreos modules come back `enc=1`; verified).
- ⚠️ **Yellow flag:** the Secure Loader revision nonce differs between your 13.52 console and the 14.00 PUP:
  ```
  console 13.52 : 60cf8821685247938b6c8123aed2a8b0b8ef9d39d9aeb2727a0c64fd810118e7
  PUP     14.00 : 7ae1c843b37e82b25656fd6a2f3b015c194a400dfb3871428bcb6bd883f6fbfe
  ```
  Caveat: the console's loader is its own per-console variant while the PUP ships 7 generic ones, so this is **not** an apples-to-apples comparison and does **not** prove the keyset changed. But it's the specific thing to resolve before betting on Stage 3.

Next actionable step: a payload that drives the console's auth-manager mailbox (`VERIFY_HEADER → LOAD_SELF_SEGMENT`) against our *own* `80010008` SELF — its required FW is 13.52 ≤ 13.52, so the console should decrypt it. That is the same build pattern as the payload that just worked.

---

## 7. Reproduce / resume

```
# 1. decrypt on console (never installs anything)
utilities -> Payloader -> pup-decrypt-1352.bin        (input: /mnt/usb0/safe.PS4UPDATE.PUP)

# 2. pull results
python download_dec.py          # PS4UPDATE1.PUP.dec -> dec/

# 3. unpack (decompress segments using the block tables)
pup-unpack.exe dec\PS4UPDATE1.PUP.dec dec\unpacked1

# 4. kernel
dec\unpacked1\secure_modules.bin  -> entry 80010002  ->  dec\80010002_kernel_14.00.self
```

## 8. Safety ledger

- The console was **never** asked to install anything. GoldHEN's `hen.ini` has `block_updates = 1` (the `/update` partition is unmounted), so an accidental install isn't possible from the console side.
- The decrypter only read `/mnt/usb0/safe.PS4UPDATE.PUP` and wrote `.dec` files back to the same stick. No flash write, no firmware change.
- Console is still on **13.52** and still jailbroken; the JB is RAM-only as always.
- USB space: outputs total 503 MB; with the 480 MB PUP that's ~1 GB of your 57 GB. Fine.
