/*
 * PS4 13.52 SELF Decrypter  —  payload
 *
 * Goal: decrypt a SELF (ultimately the 14.00 kernel SELF) to a plaintext ELF
 * by driving the console's own AuthMgr, then write the result to USB.
 *
 * Design notes
 * ------------
 * - The console is 13.52 + GoldHEN; nothing here installs or writes flash.
 * - Build is the proven ps4-payload-sdk toolchain (same as ps4-pup-decrypt).
 * - Two phases, deliberately separated:
 *
 *     PHASE 1  probe   — read the derived addresses with get_memory_dump() and
 *                        print what is actually there. Non-destructive. This is
 *                        the run that proves the static analysis on hardware.
 *
 *     PHASE 2  decrypt — kexec() a kernel worker that calls the AuthMgr API.
 *                        Only runs if /mnt/usb0/selfdec.mode contains "decrypt".
 *
 *   Phase 2 exists so that a wrong offset costs a reboot, not a bricked dump.
 *   A missing /mnt/usb0/selfdec.mode means PHASE 1 ONLY.
 *
 * All offsets come from include/offsets_1352.h (see 1352-OFFSET-DERIVATION.md).
 */

#include <assert.h>

#include "ps4.h"
#include "offsets_1352.h"
#include "self.h"

#define MODE_FILE    "/mnt/usb0/selfdec.mode"
#define IN_FILE      "/mnt/usb0/target.self"
#define OUT_FILE     "/mnt/usb0/target.elf"

/* ------------------------------------------------------------------ */
/* kernel read helper                                                   */
/* ------------------------------------------------------------------ */
static uint64_t g_kbase = 0;

static int kread(uint64_t kaddr, void *out, size_t size)
{
    /* get_memory_dump(kaddr, dump, size) is the SDK's kernel->user copy and is
       the PS4 replacement for the PS5 payload's userland pipe/direct-map
       kread. We never need dmpml4i/dmpdpi/pml4pml4i here. */
    return get_memory_dump(kaddr, (uint64_t *)out, size);
}

static int kread64(uint64_t kaddr, uint64_t *out)
{
    *out = 0;
    return kread(kaddr, out, sizeof(uint64_t));
}

/* ------------------------------------------------------------------ */
/* PHASE 1 — probe                                                      */
/* ------------------------------------------------------------------ */
static void hexbytes(char *out, const uint8_t *b, int n)
{
    static const char *H = "0123456789abcdef";
    int i;
    for (i = 0; i < n; i++) {
        out[i * 2]     = H[(b[i] >> 4) & 0xf];
        out[i * 2 + 1] = H[b[i] & 0xf];
    }
    out[n * 2] = 0;
}

/*
 * probe v2 — hardware-verify every derived FUNCTION address by reading its
 * first 8 bytes and comparing offline against czdji0/1352k.elf, then dump a
 * window around the auth-manager handle to locate the real service id.
 *
 * Pure reads. Cannot panic. Phase 2 stays unarmed without the mode file.
 */
static void probe(const char *fw)
{
    /*
     * NOTE: KO_* values are compile-time numbers, so this array needs no
     * relocation. A `static const char *` array of string addresses would
     * (R_X86_64_RELATIVE in .data.rel.ro), and objcopy -O binary does NOT
     * carry those - which is exactly what garbled the v2 logs. Never use
     * pointer arrays in this payload.
     */
    static const uint64_t fnk[6] = {
        KO_1352_FN_SERVICE_MAILBOX,     /* F0 */
        KO_1352_FN_SM_REQUEST,          /* F1 */
        KO_1352_FN_AUTHMGR_AUTHHDR,     /* F2 */
        KO_1352_FN_AUTHMGR_LOAD,        /* F3 */
        KO_1352_FN_AUTHMGR_FINALIZE,    /* F4 */
        KO_1352_FN_AUTHMGR_ISLOADABLE,  /* F5 */
    };

    char msg[190];
    char hex[64];
    uint8_t b[0x80];
    uint64_t *qw = (uint64_t *)b;
    uint32_t idx = 0;
    uint64_t buf = 0;
    int i;

    snprintf(msg, sizeof(msg), "SELFDec v5 kbase=%llx", g_kbase);
    printf_notification(msg);

    /* --- 1. function-address verification, 24 bytes each.
           The first 8 bytes of all six are identical and 16 bytes leaves
           three of them indistinguishable; 20 bytes is the true threshold,
           so read 24 for margin. Compare offline against 1352k.elf.   --- */
    for (i = 0; i < 6; i++) {
        b[0] = 0xEE;
        if (kread(g_kbase + fnk[i], b, 24) == 0) {
            hexbytes(hex, b, 24);
            snprintf(msg, sizeof(msg), "F%d %s", i, hex);
        } else {
            snprintf(msg, sizeof(msg), "F%d READFAIL", i);
        }
        printf_notification(msg);
    }

    /* --- 2. 0x80-byte window around the auth-manager handle --- */
    if (kread(g_kbase + KO_1352_AUTHMGR_HANDLE, b, sizeof(b)) == 0) {
        for (i = 0; i < 4; i++) {
            snprintf(msg, sizeof(msg), "H%x %llx %llx %llx %llx",
                     i * 0x20,
                     qw[i * 4 + 0], qw[i * 4 + 1],
                     qw[i * 4 + 2], qw[i * 4 + 3]);
            printf_notification(msg);
        }
    } else {
        printf_notification("H window READFAIL");
    }

    /* --- 3. context table, re-confirmed --- */
    for (i = 0; i < KO_1352_AUTHMGR_CTX_COUNT; i++) {
        uint64_t base = g_kbase + KO_1352_AUTHMGR_CTX_TABLE
                        + (uint64_t)i * KO_1352_AUTHMGR_CTX_STRIDE;
        idx = 0; buf = 0;
        kread(base + CTX_OFF_INDEX, &idx, sizeof(idx));
        kread64(base + CTX_OFF_BUFFER, &buf);
        snprintf(msg, sizeof(msg), "ctx[%d] idx=%u buf=%llx", i, idx, buf);
        printf_notification(msg);
    }

    /* --- 4. head of ctx[0]'s 0x1000 buffer --- */
    {
        uint64_t c0base = g_kbase + KO_1352_AUTHMGR_CTX_TABLE;
        uint64_t c0buf = 0;
        kread64(c0base + CTX_OFF_BUFFER, &c0buf);
        if (c0buf && kread(c0buf, b, 0x20) == 0) {
            snprintf(msg, sizeof(msg), "ctxbuf %llx %llx %llx %llx",
                     qw[0], qw[1], qw[2], qw[3]);
            printf_notification(msg);
        } else {
            printf_notification("ctxbuf READFAIL");
        }
    }
}

/* ------------------------------------------------------------------ */
/* PHASE 2 — kernel worker                                              */
/* ------------------------------------------------------------------ */

/*
 * [P] SIGNATURE STATUS — see 1352-OFFSET-DERIVATION.md §14.
 *
 * All six entry-point ADDRESSES are hardware-confirmed (v3 probe, byte-exact).
 * The ARGUMENT LAYOUTS are only partly mapped:
 *
 *   fin      (ctx)                                       1 arg   CONFIRMED
 *   smreq    (ctx, arg, _, auth_info_in, auth_info_out)           CONFIRMED §11.2
 *   mailbox  (service_id, in, out)                       3 args  rdx confirmed
 *   isload                                               >=4 args
 *   authhdr                                              >=6 args   ** NOT 4 **
 *   load                                                 7 args     ** NOT 5 **
 *
 * The typedefs below are therefore KNOWN WRONG for authhdr and load: calling
 * them as written leaves r9 and two stack slots carrying garbage and would very
 * likely crash the console.
 *
 * DECISION (§14.3): do NOT call the public API yet. Drive the SM layer instead
 * (smreq + mailbox, whose signatures ARE confirmed) with orbital's PS4-native
 * command sequence. decrypt_worker() is therefore hard-disabled below until it
 * is rewritten against smreq/mailbox.
 */
/*
 * sceSblAuthMgrIsLoadable — signature FULLY DERIVED from its own body
 * (1352-OFFSET-DERIVATION.md §15):
 *
 *   etype         edi  -> moved to ebx, then `cmp ebx,3 / ja error`, and used
 *                         to index the per-type counter array at koff 269C130.
 *                         So: 0..3, selects which auth-manager context is used.
 *   auth_info_in  rsi  -> NULL-checked, moved to r12, becomes smreq's rcx.
 *   path          rdx  -> moved to rdi for the path classifier at koff 3B3630;
 *                         its return value becomes smreq's command argument.
 *                         So this is a STRING like "/system_ex/".
 *   auth_info_out rcx  -> NULL-checked, moved to r14, becomes smreq's r8.
 *
 * IsLoadable does the whole job internally: validates, picks/increments the
 * context, classifies the path, and issues the SM request. That makes it the
 * only entry point we can currently call WITHOUT guessing anything.
 */
typedef int (*fn_isloadable_t)(uint32_t etype, void *auth_info_in,
                               const char *path, void *auth_info_out);

/*
 * _sceSblAuthMgrSmStart — the prologue (1352-OFFSET-DERIVATION.md §17).
 * No arguments: every incoming argument register is written before it is read.
 * Guarded on the "SM started" byte at koff 0x269C098, so calling it twice is
 * harmless. Starts the "80010008" AuthMgr secure module and writes the SM handle
 * to koff 0x269C0A0.
 */
typedef void (*fn_smstart_t)(void);

/* Deliberately unused until their arities are mapped (§14.2). Kept so the
   header values are not lost. */
typedef int (*fn_authheader_t)(void *ctx, void *hdr, uint64_t hdr_size, void *auth_info);
typedef int (*fn_loadseg_t)(void *ctx, uint32_t seg_idx, uint32_t is_block_table,
                            void *data, uint64_t size);
typedef int (*fn_loadblock_t)(void *ctx, void *block_info, uint32_t seg_idx,
                              void *data, uint64_t size);
typedef int (*fn_finalize_t)(void *ctx);

struct dec_args {
    uint64_t kbase;
    uint8_t *self_buf;      /* in:  encrypted container (userland ptr)   */
    uint64_t self_size;
    uint8_t *out_buf;       /* out: plaintext                            */
    uint64_t out_size;
    uint32_t segment_idx;   /* which segment to pull                     */
    uint32_t etype;         /* in:  which auth-manager context to use.
                                   Must index a context whose state field
                                   (ctx+0x00) is 1 or 2, or IsLoadable takes
                                   its error return instead of calling the SM. */
    uint32_t flag_before;   /* out: koff 0x269C098 before SmStart        */
    uint32_t flag_after;    /* out: koff 0x269C098 after  SmStart        */
    uint64_t handle_after;  /* out: koff 0x269C0A0 after  SmStart        */
    int32_t  result;        /* out: 0 ok, else stage code                */
    int32_t  detail;        /* out: last return value seen               */
};

/* Runs in kernel context via kexec(). Must not touch userland syscalls. */
/*
 * We run in KERNEL context, so kernel memory can be read directly - no
 * syscalls, no get_memory_dump.
 */
#define K8(kb, ko)  (*(volatile uint8_t  *)((kb) + (ko)))
#define K32(kb, ko) (*(volatile uint32_t *)((kb) + (ko)))
#define K64(kb, ko) (*(volatile uint64_t *)((kb) + (ko)))

static void decrypt_worker(struct thread *td, struct dec_args *a)
{
    /*
     * THREE STEPS, in order. Step 1 is the piece §16 was missing.
     *
     * 1. _sceSblAuthMgrSmStart()  koff 0x63E470 - no arguments, and guarded on
     *    the "SM started" byte at koff 0x269C098, so it is idempotent. It starts
     *    the "80010008" AuthMgr secure module and writes the SM handle into
     *    koff 0x269C0A0 (passed to it as arg6). Without this the transport is
     *    NULL and every request path faults - exactly what happened last run.
     *
     * 2. Re-read the flag and the handle to CONFIRM the transport came up.
     *    If the flag is still 0 we stop and do not issue the request.
     *
     * 3. sceSblAuthMgrIsLoadable(etype, in, "/system_ex/", out) - the only
     *    fully-mapped entry point (§15).
     *
     * authhdr/load are still never called (6 and 7 args, unmapped; §14.2).
     */
    static const char path[] = "/system_ex/";
    uint8_t auth_info_in[SELF_AUTH_INFO_SIZE];
    uint8_t auth_info_out[SELF_AUTH_INFO_SIZE];
    int rc;

    a->result = -1;
    a->detail = 0;
    a->flag_before = 0;
    a->flag_after = 0;
    a->handle_after = 0;

    /* --- step 1 ---------------------------------------------------- */
    a->flag_before = K8(a->kbase, KO_1352_SM_FLAG);

    ((fn_smstart_t)(a->kbase + KO_1352_FN_SM_START))();

    a->flag_after  = K8(a->kbase, KO_1352_SM_FLAG);
    a->handle_after = K64(a->kbase, KO_1352_AUTHMGR_HANDLE);

    /* --- step 2 ---------------------------------------------------- */
    if (a->flag_after == 0) {
        a->result = 3;              /* SmStart did not bring the SM up */
        return;
    }

    /* --- step 3 ---------------------------------------------------- */
    memset(auth_info_in, 0, sizeof(auth_info_in));
    memset(auth_info_out, 0, sizeof(auth_info_out));

    rc = ((fn_isloadable_t)(a->kbase + KO_1352_FN_AUTHMGR_ISLOADABLE))(
             a->etype, auth_info_in, path, auth_info_out);

    a->detail = rc;
    a->result = (rc == 0) ? 0 : 2;
}

/* ------------------------------------------------------------------ */
/* helpers                                                              */
/* ------------------------------------------------------------------ */
static int read_file(const char *path, uint8_t **out, uint64_t *out_size)
{
    int fd = open(path, O_RDONLY, 0);
    if (fd < 0)
        return -1;

    off_t sz = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    if (sz <= 0) { close(fd); return -2; }

    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) { close(fd); return -3; }

    ssize_t got = read(fd, buf, (size_t)sz);
    close(fd);
    if (got != (ssize_t)sz) { free(buf); return -4; }

    *out = buf;
    *out_size = (uint64_t)sz;
    return 0;
}

static int write_file(const char *path, const uint8_t *buf, uint64_t size)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (fd < 0)
        return -1;

    uint64_t done = 0;
    while (done < size) {
        ssize_t w = write(fd, buf + done, (size_t)(size - done));
        if (w <= 0) { close(fd); return -2; }
        done += (uint64_t)w;
    }
    close(fd);
    return 0;
}

static int mode_is_decrypt(void)
{
    int fd = open(MODE_FILE, O_RDONLY, 0);
    if (fd < 0)
        return 0;
    char b[16] = {0};
    read(fd, b, sizeof(b) - 1);
    close(fd);
    return strstr(b, "decrypt") != 0;
}

/* ------------------------------------------------------------------ */
/* entry                                                                */
/* ------------------------------------------------------------------ */
int _main(struct thread *td)
{
    char msg[160];

    initKernel();
    initLibc();
    initPthread();
    initNetwork();
    initSysUtil();

    char fw[16] = {0};
    if (get_firmware_string(fw) != 0)
        strcpy(fw, "unknown");

    printf_notification("SELFDec: starting");

    /* kernel base from LSTAR (xfast_syscall), same mechanism as the SDK's
       get_kernel_base()/copyout_macro. */
    g_kbase = get_kernel_base();
    if (!g_kbase) {
        printf_notification("SELFDec ABORT: no kernel base");
        return 0;
    }

    /* ensure we hold full privileges before touching anything */
    jailbreak();
    mmap_patch();

    /* ---- PHASE 1 : always run, always safe ------------------------- */
    probe(fw);

    /* ---- PHASE 2 : opt-in only ------------------------------------- */
    if (!mode_is_decrypt()) {
        printf_notification("SELFDec: probe only (no mode file)");
        return 0;
    }

    /*
     * STAGE 1 NEEDS NO TARGET FILE. IsLoadable is called with benign zeroed
     * buffers and a path string, so it can run standalone. Reading
     * /mnt/usb0/target.self belongs to stage 2, which is not written yet - the
     * previous build wrongly gated stage 1 behind that read, so the armed run
     * bailed out before ever calling.
     */
    struct dec_args args;
    memset(&args, 0, sizeof(args));
    args.kbase = g_kbase;

    uint32_t i;

    /*
     * Pick a context whose state field says it is ACTIVE. IsLoadable requires
     * ctx[etype] state (at +0x00) to be 1 or 2; otherwise it returns an error
     * without ever reaching the secure module, which would tell us nothing.
     * If no context is active we do not call at all.
     */
    args.etype = 0xFFFFFFFFu;
    for (i = 0; i < KO_1352_AUTHMGR_CTX_COUNT; i++) {
        uint32_t st = 0;
        uint64_t cb = g_kbase + KO_1352_AUTHMGR_CTX_TABLE
                      + (uint64_t)i * KO_1352_AUTHMGR_CTX_STRIDE;
        kread(cb + CTX_OFF_STATE, &st, sizeof(st));
        snprintf(msg, sizeof(msg), "ctx[%u] state=%u", i, st);
        printf_notification(msg);
        if ((st == 1 || st == 2) && args.etype == 0xFFFFFFFFu)
            args.etype = i;
    }

    if (args.etype == 0xFFFFFFFFu) {
        printf_notification("SELFDec: no active ctx - not calling");
        unlink(MODE_FILE);
        return 0;
    }

    snprintf(msg, sizeof(msg), "SELFDec: call IsLoadable etype=%u", args.etype);
    printf_notification(msg);

    /* execute in kernel context */
    kexec(decrypt_worker, (void *)&args);

    snprintf(msg, sizeof(msg), "SELFDec: smflag %u->%u handle=%llx",
             args.flag_before, args.flag_after, args.handle_after);
    printf_notification(msg);

    snprintf(msg, sizeof(msg), "SELFDec: stage=%d rc=%d", args.result, args.detail);
    printf_notification(msg);

    /* read the flag/handle from userland too, as a cross-check on the worker */
    {
        uint32_t f = 0;
        uint64_t h = 0;
        kread(g_kbase + KO_1352_SM_FLAG, &f, sizeof(f));
        kread64(g_kbase + KO_1352_AUTHMGR_HANDLE, &h);
        snprintf(msg, sizeof(msg), "SELFDec: after flag=%u handle=%llx", f, h);
        printf_notification(msg);
    }

    /*
     * AUTO-DISARM. Remove the mode file so a bad result cannot repeat itself on
     * the next launch: without it the payload reverts to probe-only. This also
     * means an unplanned reboot mid-run does not leave the risky path armed.
     */
    if (unlink(MODE_FILE) != 0) {
        /* FAT may refuse; harmless - we can also disarm over FTP. */
        printf_notification("SELFDec: disarm failed (remove selfdec.mode)");
    }

    /*
     * STAGE 2 placeholder. When the worker is rewritten against the SM layer,
     * target.self is read here, the segment pulled, and the plaintext written
     * to OUT_FILE.
     */
    return 0;
}
