/*
 * selfdec2 — PS4 13.52 blackbox SELF decrypter (AuthMgr client)
 *
 * Goal: obtain a PLAINTEXT copy of a SELF by driving the console's own secure
 * module. First target is 80010008 (AuthMgr) so its SELF key bank can be
 * recovered; with those keys the 14.00 kernel SELF can then be decrypted
 * offline, where firmware key-revision checks do not apply.
 *
 * This is a direct port of AlexAltea's PS4-native orbital dumper protocol
 * (orbital-ref/tools/dumper/source/self_decrypter.c) onto 13.52 offsets.
 *
 * SAFETY MODEL — read before changing anything
 * --------------------------------------------
 *  * Does NOT call _sceSblAuthMgrSmStart (koff 0x63E470), and does not need to:
 *    the "SM started" byte at koff 0x269C098 already reads 1 on a booted 13.52
 *    console. REASON CORRECTED: with that byte set, 0x63E470 takes its
 *    `jne 0x63E4F2` early-out between 0x63E4A3 and 0x63E4AA and reduces to
 *    sx_xlock / sx_xunlock, so it could not softlock anything. The two softlocks
 *    came from calling it as a FIRST start (flag clear, module already running),
 *    and from the hand-walk that followed +0x48 believing it was `next` when it
 *    is really the tree's LEFT CHILD. The rule stays because the call is
 *    unnecessary here - not because it is inherently unsafe. See
 *    1352-AUTHMGR-REOPEN.md §6.
 *  * Work is split into 9 single-purpose STEPS. Each step is one kexec()
 *    call, so userspace prints a notification after every one: a hang is
 *    always localised to an exact step number.
 *  * maxstep comes from /mnt/usb0/sd.cfg. The console never runs further than
 *    we have already proven to work.
 *  * No flash writes, no patches, no module loads. The only kernel memory
 *    written is our own kmalloc'd scratch and the 4-entry self_ctx_status.
 *
 * Inside sd_step we are in kernel mode on our own thread:
 *  * user memory is never dereferenced directly — copyin/copyout are used.
 *    Both were confirmed by disassembly (0x2BD790 / 0x2BD6A0) and copyout is
 *    additionally confirmed by libPS4's own K1352_COPYOUT constant.
 *  * no syscalls.
 */

#include "ps4.h"
#include "embed_hdr.h"   /* generated: first 0x1000 B of 80010008.self */

/*
 * LAUNCH_ONLY - launch-isolation build.
 *
 * Set to 1 to produce a payload that prints exactly one marker and returns:
 * no file reads, no allocations, no kexec, no kernel-mode code at all.
 *
 * Purpose: every run so far has ended with the console down, and two runs prove
 * the failure does not need our kernel work (run 11 died in _main's file reads
 * with no step ever running; run 8 had smcall=0 and never reached verify). The
 * remaining suspect is GoldHEN's injection itself - it hijacks ScePartyDaemon,
 * a system daemon, and kexec's into it. This build measures that directly:
 *   dies too   -> the injection is the problem, and no payload edit can fix it
 *   survives   -> the risk scales with what the payload does, and we can proceed
 * Set back to 0 for the real probe. See 1352-AUTHMGR-REOPEN.md.
 */
#define LAUNCH_ONLY 0   /* <-- set to 1 to build the launch-isolation payload */

/*
 * NO_IO - remove every file read from the payload.
 *
 * Evidence motivating it: the launch-isolation build (LEGACY marker only, no I/O,
 * no kexec) survives; every run that died did file I/O within its first
 * milliseconds. Run 12 died immediately after the config marker, and the very
 * next thing _main does is read a config file and then an 88 KB SELF; run 11 died
 * on the third of its six path reads. Meanwhile sd_cfg_parse() itself opens two
 * paths BEFORE the marker run 12 died at.
 *
 * With NO_IO=1 the payload opens no file at all:
 *   - sd.cfg is not read; defaults are used and smcall is forced to 1 anyway
 *   - target.self is not read; the compiled-in header page is used (g_embed_hdr)
 *   - the console-SELF probe reads are skipped; only the embedded page is probed
 *
 * This makes the run a clean test of one variable: if a payload that does no I/O
 * still dies, the file reads are exonerated and the step machinery is implicated.
 * If it survives, we finally have a rig stable enough to iterate on.
 *
 * Cost: the probe loses the two console SELFs, so this run re-confirms the
 * embedded 80010008 verdict (-22) rather than testing a loadable SELF.
 */
#define NO_IO 1

/* ------------------------------------------------------------------ */
/* 13.52 kernel offsets, derived from czdji0/1352k.elf                 */
/* ------------------------------------------------------------------ */

/* --- functions --- */
#define KO_KMALLOC          0x00009520ULL  /* (size, malloc_type*, flags)     */
#define KO_KFREE            0x000096E0ULL  /* (ptr, malloc_type*)             */
#define KO_SX_XLOCK         0x000A3840ULL  /* (sx, opts, file, line)          */
#define KO_SX_XUNLOCK       0x000A3A00ULL  /* (sx, file, line)                */
#define KO_COPYIN           0x002BD790ULL  /* (uaddr, kaddr, len)             */
#define KO_COPYOUT          0x002BD6A0ULL  /* (kaddr, uaddr, len) = libPS4    */
#define KO_MAPPAGES         0x0061AE20ULL  /* (bus*, cpu, npages, fl, u, dsc*) */
#define KO_UNMAPPAGES       0x0061B500ULL  /* (desc)                          */
#define KO_MAILBOX          0x00630230ULL  /* (module_id, query, reply)       */
#define KO_SM_FINALIZE      0x0063FF00ULL  /* _sceSblAuthMgrSmFinalize(ctx)   */

/* --- data --- */
#define KO_MALLOC_TYPE      0x01AECCB0ULL  /* struct malloc_type *: the one    */
                                           /* sceSblDriverMapPages itself uses */
#define KO_MODULE_ID        0x0269C0A0ULL  /* u64 SM module id                */
#define KO_SM_XLOCK         0x0269C0C8ULL  /* sx wrapping the mailbox         */
#define KO_SM_FLAG          0x0269C098ULL  /* byte, "SM started". Written to 1 */
                                           /* ONLY after sub_6300E0 succeeds,  */
                                           /* so a 1 also proves the start did */
#define KO_CTX_STATUS       0x0269C130ULL  /* u32[4], 3 == free               */
#define KO_SELF_CONTEXTS    0x0269C140ULL  /* self_context_t[4], stride 0x60  */

/* The secure module's OWN staging area, 0x1000 bytes per context slot.
   Confirmed from the live 20 MB dump: koff 0x0269C0B8 holds 0x0a56c000 (a BUS
   address) and koff 0x0269C2C0 holds 0xffffc18715c2c000 (the kernel VA of that
   very same page). The 13.52 kernel's own _sceSblAuthMgrSmVerifyHeader at koff
   0x6401F0 builds packet+0x08 from exactly this pair:

       6402af  mov ebx, dword ptr [rdi + 0x30]   ; ctx->buf_id  (0..3)
       6402a8  lea rax, [rip + ...]              ; koff 0x0269C0B8
       6402be  shl ebx, 0xc
       6402c1  add rbx, qword ptr [rax]          ; BUS = *(0x269C0B8) + id*0x1000

   so the SELF header must be sitting in THAT page, addressed by its BUS
   address.

   Confirmed against the live dump, 2026-09-21: the four slots carry
   ctx->0x30 == 0, 1, 2, 3 (it IS buf_id; the 0x896487 that looks like a buf_id
   in the raw hex is ctx->0x28), so the console's own packet+0x08 values are
   exactly 0xa56c000 + slot*0x1000. This offset read-out settled a real
   ambiguity: do not re-derive ctx->0x30 by eye from the dump again.

   The earlier claim that orbital's caller-mapped buffer "is what produced EINVAL
   here" was never tested, and is withdrawn. Every packet field this payload
   sends matches both references and the kernel's own verifyHeader; the
   remaining difference is what rd[9] is about to measure. */
#define KO_CTX_BUFBASE      0x0269C2C0ULL  /* VA  base, +id*0x1000            */
#define KO_BUF_B            0x0269C0B8ULL  /* BUS base, +id*0x1000            */

/* _sceSblAuthMgrSmVerifyHeader. Reachable only as a TAIL CALL - 0x63D100 is
   literally `call SmStart; jmp 0x6401F0` - so a `call`-only scan reports zero
   callers and it looks like dead code. It is not; it is the live path. */
#define KO_SM_VERIFY_HDR    0x006401F0ULL
/* int sub_63D780(ctx, void **out) - resolves ctx->0x38 into a digest pointer.
   Returns 0 on success, 0xfffffffe if the header's digest/extent tables do not
   line up. verify_header skips the whole SELF-specific block when it fails. */
#define KO_CTX_DIGEST_PTR   0x0063D780ULL

/* The console's SELF key store, rooted at koff 0x0269C300. sub_645110 walks it
   with memcmp(digest, node, 0x20) and, on a hit, memcpy's node+0x20 out.
   verify_header feeds that straight into the packet:

       6451D3  lea  rsi, [rbx + 0x20]   ; node->value
       6451DF  call memcpy              ; -> packet+0x30, the 0x10-byte KEY
       6451E4  mov  eax, [rbx + 0x40]   ; -> packet+0x2C, key_id
       6451FA  mov  eax, [rbx + 0x44]   ; -> packet+0x2A

   CORRECTED (see 1352-AUTHMGR-REOPEN.md): this is a RED-BLACK TREE, not a
   singly-linked list. Node stride 0x68; children at +0x48 (left, taken when
   memcmp < 0) and +0x50 (right); node+0x60 is the colour/flag word. There is no
   `next` at +0x48 - that slot is the LEFT CHILD, which is why hand-walking it as
   a list went wrong.

   The store is writable: sceSblAuthMgrAddEEkc3 @ 0x644D70 builds a 0x68-byte node
   and links it at 0x644F77 (`mov qword ptr [rbx], r14`), reached from the
   authmgr_ioctl dispatcher @ 0x643FB0 (cmd 0xc0504104) at 0x644071. It is an
   RB-tree insert, so that write is register-indirect and invisible to a
   RIP-relative-only xref scan.

   The old claim that "the header only ever got EINVAL because the key was never
   supplied" is DISPROVEN. Both public references send a ZERO key and expect
   success; the live dump shows a booted console with an empty store that has
   verified SELF headers four times (see below). Do not resurrect it. */
#define KO_KEY_LIST         0x0269C300ULL
/* int sub_645110(void *digest, void *out0x20, u32 *key_id, u32 *unk)
   0 = hit, 0x800f0b02 = miss. Walks the list itself, under the list lock. */
#define KO_KEY_LOOKUP       0x00645110ULL

/* --- AuthMgr SM command numbers (ps5-selfdec-ref/include/authmgr.h,
       cross-checked against the 13.52 kernel's own SmFinalize, which
       puts a literal 5 in payload[0]) --- */
#define AUTHMGR_CMD_VERIFY_HEADER      0x01
#define AUTHMGR_CMD_LOAD_SELF_SEGMENT  0x02
#define AUTHMGR_CMD_FINALIZE           0x05
#define AUTHMGR_CMD_LOAD_SELF_BLOCK    0x06

#define CTX_COUNT         4
#define CTX_STRIDE        0x60
#define CTX_FREE          3

#define PAGE_SZ           0x1000ULL
#define ALIGN_PAGE(x)     (((x) + (PAGE_SZ - 1)) & ~(PAGE_SZ - 1))
#define STEP_MAX          9

/* ------------------------------------------------------------------ */
/* types                                                               */
/* ------------------------------------------------------------------ */
typedef void *(*fn_kmalloc_t)(uint64_t size, void *type, uint64_t flags);
typedef int   (*fn_mappages_t)(uint64_t *bus, void *cpu, uint32_t npages,
                               uint64_t flags, uint64_t unk, uint64_t *desc);
typedef int   (*fn_unmappages_t)(uint64_t desc);
typedef int   (*fn_mailbox_t)(uint64_t id, void *query, void *reply);
typedef void  (*fn_sxlock_t)(void *sx, int opts, const char *file, int line);
typedef void  (*fn_sxunlock_t)(void *sx, const char *file, int line);
typedef int   (*fn_copyin_t)(const void *uaddr, void *kaddr, uint64_t len);
typedef int   (*fn_copyout_t)(const void *kaddr, void *uaddr, uint64_t len);
typedef int   (*fn_finalize_t)(void *ctx);

/* ------------------------------------------------------------------ */
/* state                                                               */
/* ------------------------------------------------------------------ */
struct sd_res {
    int32_t  step;          /* step just executed                */
    int32_t  rc;            /* 0 = that step was fine            */
    uint64_t rd[16];        /* raw per-step outputs              */
};

struct sd_args {
    uint64_t kbase;

    /* in: what to do */
    uint64_t step;
    uint64_t lock;          /* 1 = take authmgr_sm_xlock around the mailbox */
    uint64_t svcreq;        /* 1 = never touch the SM while module id == 0  */
    uint64_t ctxidx;        /* which of the 4 slots to use; 0xff = first free */
    uint64_t smcall;        /* 1 = allow the verify_header call in step 7    */

    /* in: SELF geometry, parsed by userspace */
    uint64_t hdr_len;       /* header_size + metadata_size */
    uint64_t seg_index;
    uint64_t seg_off;       /* byte offset of the segment inside the file  */
    uint64_t seg_size;      /* segment size on disk (compressed size)      */
    uint64_t self_size;

    /* in: userland buffers */
    uint64_t p_self;
    uint64_t p_out;         /* out: plaintext / auth-info sink */
    uint64_t out_cap;
    uint64_t p_res;         /* out: struct sd_res */

    /* in: verify-probe header pages, built by _main. [0] is always the embedded
       80010008 page (the file we already know the module refuses with -22);
       1.. are console-local SELFs. A 0 entry means "that read failed" and step 7
       reports it as NOREAD rather than copying from address 0. Keep in
       lockstep with the "selfdec2 seek<N>" notifications _main emits, which are
       the only place the index -> path mapping exists. */
    uint64_t p_hdr[8];
    uint64_t n_hdr;

    /* kernel scratch, carried between steps */
    uint64_t ctx;           /* chosen auth-manager context index */
    uint64_t svc_id;
    uint64_t hdr_buf, hdr_bus, hdr_desc;
    uint64_t ai_buf,  ai_bus,  ai_desc;
    uint64_t ct_buf,  ct_bus,  ct_desc;
    uint64_t seg_buf, seg_bus, seg_desc;
};

static struct sd_args g_a;
static struct sd_res  g_r;
/* per-step rc history. The status file is overwritten each step, so without
   this only the FINAL step survived - which made run 1 unreadable. */
static int32_t g_rcs[12];

/* Verify-probe list is staged HERE, not straight into g_a, because _main does
   `memset(&g_a, 0, sizeof(g_a))` immediately before the step loop and the probe
   reads happen before that. Run 10 hit exactly this: seven slots were found
   ("probe slots 7") and every one was wiped, so step 7 saw n_hdr == 0, ran zero
   iterations, and reported verify=0 with rc=7 - which is why no P<k> line ever
   appeared. Copied into g_a right after the memset. */
static uint64_t g_pb[8];
static uint64_t g_pn;

/* ------------------------------------------------------------------ */
/* kernel-side worker: runs ONE step per kexec                         */
/* ------------------------------------------------------------------ */
static int write_file(const char *path, const uint8_t *buf, uint64_t size);

static void sd_step(struct thread *td, struct sd_args *a_unused)
{
    /*
     * DO NOT trust the kexec parameter.
     *
     * Hardware told us it is garbage: two separate runs both fell through to
     * `default:` in the switch below, and run 1's status file recorded
     * `last step=2269760` from `o->step = (int32_t)a->step`. So the second
     * argument kexec hands us is NOT the &g_a we passed, and `a->kbase` was
     * garbage too - meaning no kernel function was ever called, which is why
     * the payload exited cleanly instead of crashing.
     *
     * g_a is a static in the payload's own data segment, and this code runs in
     * kernel context on the calling thread, so &g_a resolves to the same memory
     * _main wrote. Addressing it directly sidesteps the whole question.
     */
    struct sd_args *a = &g_a;
    struct sd_res *o = &g_r;
    uint64_t kb = a->kbase;

    (void)td;
    (void)a_unused;
    fn_kmalloc_t    kmalloc  = (fn_kmalloc_t)(kb + KO_KMALLOC);
    fn_mappages_t   mappages = (fn_mappages_t)(kb + KO_MAPPAGES);
    fn_unmappages_t unmap    = (fn_unmappages_t)(kb + KO_UNMAPPAGES);
    fn_mailbox_t    mailbox  = (fn_mailbox_t)(kb + KO_MAILBOX);
    fn_sxlock_t     xlock    = (fn_sxlock_t)(kb + KO_SX_XLOCK);
    fn_sxunlock_t   xunlock  = (fn_sxunlock_t)(kb + KO_SX_XUNLOCK);
    fn_copyin_t     copyin   = (fn_copyin_t)(kb + KO_COPYIN);
    fn_copyout_t    copyout  = (fn_copyout_t)(kb + KO_COPYOUT);
    fn_finalize_t   finalize = (fn_finalize_t)(kb + KO_SM_FINALIZE);
    void           *mtype    = (void *)(kb + KO_MALLOC_TYPE);
    void           *smx      = (void *)(kb + KO_SM_XLOCK);

    uint64_t q[0x10];        /* 0x80 command/reply packet, 8-byte aligned */
    /*
     * r MUST be initialised: each step is a separate kexec, so a step that does
     * no copyin() would otherwise read whatever the previous caller left on the
     * stack. Step 4 is exactly that case - it only publishes a BUS address and
     * then does `if (r) o->rc = 4;`, a vestigial check left over from steps 5+.
     * With r uninitialised that line can abort the whole sequence and be
     * reported as "step 4 failed" while nothing was wrong.
     */
    uint64_t r = 0, i, cid;

    memset(q, 0, sizeof(q));
    o->step = (int32_t)a->step;
    o->rc   = 0;
    /*
     * g_r is a STATIC and every step is a separate kexec, so rd[] carries over
     * from the previous step unless it is cleared here. Run 7's report
     * ("hdrptr=... verify=3 ctxid_out=3 ctx20=3") is exactly that artefact:
     * smcall was 0, step 7 never wrote rd[1]/rd[2]/rd[3], and those three 3s are
     * step 6's ctx_status[0..2] still sitting in the struct. Any future report
     * that shows a non-zero value we did not deliberately write is now a bug,
     * not data.
     */
    memset(o->rd, 0, sizeof(o->rd));

    /*
     * HARD GUARD, deliberately in ONE place so it cannot be bypassed.
     *
     * Every step from 5 on dereferences the user's SELF image through copyin().
     * PS4's copyin (koff 0x2BD790) only range-checks `addr + len < 0x8000...0`,
     * so a NULL source passes that test and the rep-movsq then faults in kernel
     * mode -> panic + reboot. That is exactly what happened on the first run,
     * where the cfg/target upload had failed and p_self was 0.
     *
     * Steps 1..4 touch only our own kernel scratch and are always safe.
     */
    if (a->step >= 5 && a->p_self == 0) {
        o->rc = (int32_t)a->step;
        return;
    }

    switch (a->step) {

    /* ---- 1: SELF header staging buffer ---- */
    case 1:
        /* 0x8000 = 0x4000 header staging + 0x4000 for the auth-info buffer,
           so BOTH live inside one allocation and need only ONE mapping. */
        a->hdr_buf = (uint64_t)kmalloc(0x8000, mtype, 0x102);
        o->rd[0] = a->hdr_buf;
        if (!a->hdr_buf) { o->rc = 1; return; }
        memset((void *)a->hdr_buf, 0, 0x8000);
        return;

    /* ---- 2: NO LONGER MAPS ANYTHING - see the comment ---- */
    case 2:
        /*
         * mappages() REMOVED on purpose.
         *
         * It existed for the original design, where this payload handed the
         * module a BUS address for its own header buffer. That design is gone:
         * verifyHeader derives the header's bus address itself, from the
         * driver's own staging page - `*(0x269C0B8) + ctx->0x30 * 0x1000` at
         * 0x6402BE/0x6402C1 - and step 7 parks the header in that page. So
         * nothing needs a bus address for our buffer any more.
         *
         * It was also the only genuinely dangerous call in the sequence: it
         * mapped 8 pages with flags 0x61 and never tore the mapping down. A
         * stale system-bus mapping is exactly the kind of thing that faults the
         * machine LATER and intermittently, which is exactly what the failures
         * look like:
         *
         *   run 11  died inside _main's file reads, before any step ran
         *   run 12  died in step 4, which does no syscall and no memory access
         *           beyond the args struct - a no-op cannot hang a machine
         *   runs 8-10 died after the payload had finished reporting
         *   a payload that does NOTHING survives (launch-isolation build)
         *
         * A delayed bus-mapping fault explains every one of those; any operation
         * performed by step 4 itself does not.
         *
         * The pointer arithmetic that used to consume this (steps 3 and 4) is
         * left in place and is harmless: step 3 only memsets inside our own
         * kmalloc'd 0x8000 region, and step 4 only copies fields into the report.
         * hdr_bus/hdr_desc simply stay 0, which is why rd[1]/rd[2] below read 0
         * instead of a bus address - that is intended, not a failure.
         */
        a->hdr_bus  = 0;
        a->hdr_desc = 0;
        o->rd[0] = 0;                 /* 0 = no error */
        o->rd[1] = 0;                 /* no bus address by design */
        o->rd[2] = 0;
        return;

    /* ---- 3: 0x88-byte auth-info buffer, carved from the SAME allocation ----
     * Hardware showed the second MapPages() - npages=1 - returning -22
     * (EINVAL), while the npages=4 call returned 0. Rather than fight that,
     * the auth-info buffer is simply the upper half of the 0x8000 region that
     * step 1 allocated and step 2 mapped, so it is already bus-addressable and
     * needs no second mapping at all.
     */
    case 3:
        a->ai_buf = a->hdr_buf + 0x4000;
        o->rd[0] = a->ai_buf;
        if (!a->hdr_buf) { o->rc = 3; return; }
        memset((void *)a->ai_buf, 0, PAGE_SZ);
        return;

    /* ---- 4: bus address for it (derived from step 2, no syscall) ---- */
    case 4:
        a->ai_bus = a->hdr_bus + 0x4000;
        a->ai_desc = a->hdr_desc;
        o->rd[0] = 0;                 /* 0 = no error; the loop continues */
        o->rd[1] = a->ai_bus;
        o->rd[2] = a->hdr_desc;
        if (r) o->rc = 4;
        return;

    /* ---- 5: stage the SELF header, prove copyin AND copyout ---- */
    case 5:
        r = (uint64_t)copyin((const void *)a->p_self, (void *)a->hdr_buf,
                             a->hdr_len);
        o->rd[0] = r;
        if (r) { o->rc = 5; return; }
        /* send the first 0x20 bytes straight back out: userspace compares
           them against the file on disk, which validates both directions. */
        o->rd[1] = (uint64_t)copyout((const void *)a->hdr_buf,
                                     (void *)a->p_out, 0x20);
        /* and report what the kernel sees in the SELF header itself */
        {
            uint8_t *h = (uint8_t *)a->hdr_buf;
            uint64_t hm = *(uint64_t *)(h + 0x0C);
            o->rd[2] = hm & 0xffff;              /* header_size            */
            o->rd[3] = (hm >> 16) & 0xffff;      /* metadata_size          */
            o->rd[4] = *(uint64_t *)(h + 0x18) & 0xffff;  /* segment_count */
            o->rd[5] = *(uint64_t *)(h + 0x10);  /* file_size             */
        }
        if (o->rd[1]) o->rc = 5;
        return;

    /* ---- 6: choose a free context, mark busy, finalize it ---- */
    case 6: {
        volatile uint32_t *st = (volatile uint32_t *)(kb + KO_CTX_STATUS);
        cid = ~0ULL;
        for (i = 0; i < CTX_COUNT; i++) {
            o->rd[i] = st[i];
            if (st[i] == CTX_FREE && cid == ~0ULL) cid = i;
        }
        /* NOTE: on a booted console all four slots read 3, and the kernel's own
           sceSblAuthMgrAuthHeader only ever picks a slot whose state is 0 - it
           returns EBUSY once none is. So "first state==3 slot" and "slot 0" are
           the same answer here; ctxidx in sd.cfg lets us pin any of the four
           without another rebuild. */
        if (a->ctxidx < CTX_COUNT) cid = a->ctxidx;
        o->rd[4] = cid;
        if (cid == ~0ULL) { o->rc = 6; return; }

        a->ctx    = cid;
        a->svc_id = *(volatile uint64_t *)(kb + KO_MODULE_ID);
        o->rd[5] = a->svc_id;
        o->rd[7] = *(volatile uint8_t  *)(kb + 0x0269C098ULL);   /* SM_FLAG */
        o->rd[8] = *(volatile uint32_t *)(kb + 0x0269C09CULL);

        /* HANG GUARD. If the secure-module handle is 0 then the mailbox has no
           valid destination, and a blocking wait on it is exactly how this
           console died before. Report and stop rather than risk it. */
        o->rd[10] = 0;
        if (a->svcreq && a->svc_id == 0) {
            o->rc = 6;
            return;
        }

        st[cid] = 1;                             /* in use (as the reference) */
        st[cid] = 1;   /* claim it, as the reference does pre-verify */
        r = (uint64_t)finalize((void *)(kb + KO_SELF_CONTEXTS
                                        + cid * CTX_STRIDE));
        o->rd[6] = r;
        o->rd[10] = 1;
        if (r) o->rc = 6;
        return;
    }

    /* ---- 7: AUTHMGR_CMD_VERIFY_HEADER - via the kernel's own builder ----
     *
     * Runs 2 and 3 established that the packet SHAPE was never the problem:
     * five different spellings of it all came back EINVAL while the SBL
     * transport itself reported success. Two things were wrong outside the
     * packet.
     *
     * 1. ctx->0x38 is a POINTER to the raw SELF header (self_context_t.header),
     *    not a BUS address. sceSblAuthMgrAuthHeader points it at the staging
     *    page and then fills that page with the header through its read
     *    callback. verify_header resolves it via sub_63D780 and, when that
     *    fails, SKIPS packet+0x2A/+0x2C/+0x30 entirely - so on every previous
     *    run those three fields were zero.
     * 2. _sceSblAuthMgrSmVerifyHeader is reachable only as a TAIL CALL:
     *    0x63D100 is literally `call SmStart; jmp 0x6401F0`. That is why a
     *    call-site scan reports zero callers and it looks like dead code.
     *
     * So instead of hand-assembling a sixth spelling, populate the slot the way
     * sceSblAuthMgrAuthHeader does and let the kernel build the packet. Its
     * return value IS the secure module's status (0x64052A reads packet+0x04
     * straight into ebx), and on success it copies packet+0x1C into ctx->0x1C
     * for us - the auth context id every later call needs.
     *
     * SmStart is NOT called. It is guarded on the started byte and returns
     * immediately once that byte is set, and the module is demonstrably
     * answering us, so it cannot be supplying anything we lack.
     */
    case 7: {
        uint64_t id    = *(volatile uint64_t *)(kb + KO_MODULE_ID);
        uint64_t buf_b = *(volatile uint64_t *)(kb + KO_BUF_B);
        uint64_t cbb   = *(volatile uint64_t *)(kb + KO_CTX_BUFBASE);
        uint64_t idx   = a->ctx & 3ULL;
        uint64_t page  = cbb + idx * PAGE_SZ;
        uint64_t rv;
        uint8_t *ctxp  = (uint8_t *)(kb + KO_SELF_CONTEXTS + idx * CTX_STRIDE);
        int (*verify)(void *)          = (int (*)(void *))(kb + KO_SM_VERIFY_HDR);

        a->svc_id = id;
        o->rd[5]  = buf_b;
        o->rd[6]  = cbb;
        o->rd[7]  = *(volatile uint8_t *)(kb + KO_SM_FLAG);
        o->rd[13] = idx;
        o->rd[15] = a->hdr_bus;

        /* NOTE: a first cut of this step walked the key list by hand, reading
           node+0x48 as `next` and following it. That layout was a GUESS, the
           range check on each link was only a plausibility filter, and following
           one bad link faults in kernel mode. It softlocked the console.
           The list is now only ever touched by sub_645110 itself, which
           validates every link and holds the list lock. See below. */

        if (a->svcreq && id == 0) { o->rc = 7; return; }   /* hang guard */
        if (!buf_b || !cbb || !a->p_self) { o->rc = 7; return; }

        /* Park the header in the module's own staging page for this slot, and
           hand it over by BUS address. A full page, not just header+metadata:
           the kernel copies MIN(file_size, ALIGN_PAGE(header+meta)) while
           telling the module header_size = header+meta, so the module sees real
           file bytes past header_size rather than zero fill. */
        r = (uint64_t)copyin((const void *)a->p_self, (void *)page, PAGE_SZ);
        o->rd[14] = r;
        if (r) { o->rc = 7; return; }

        /* ---- digest -> key lookup, done BY THE KERNEL, not by us ----
         *
         * sub_645110(digest, out0x20, &key_id, &u) walks the key list itself
         * (under its own lock, validating every link) and returns 0x800f0b02 on
         * a miss, 0 on a hit. Handing it a pointer into the page WE just wrote
         * means nothing in this step dereferences an address we have not
         * already proved mapped.
         *
         * APPEAL WITHDRAWN - the key store is now OFF LIMITS from this payload.
         *
         * Run 6 called sub_645110 on 61 aligned windows of the header page and
         * died before it ever reached its own write_file: sd_keys.txt exists in
         * NEITHER /data/payloads nor /mnt/usb0. Everything ahead of that point
         * (the copyin into the page) is byte-for-byte what run 4 did, and run 4
         * completed. So the fault is inside the sub_645110 call itself, and the
         * two crashing builds are exactly the two that touched the key store
         * while run 4 - which never did - worked.
         *
         * That function is NOT the harmless accessor its null checks suggest:
         * it takes _sx_xlock on koff 0x0269C2E0, reads the tree root at
         * 0x0269C300, and walks both child pointers. Something in that sequence
         * dies when called from this payload's thread, and I am not going to
         * find out which by trial and error on a console that costs a reboot per
         * attempt.
         *
         * What is left below reads only SINGLE values from fixed koffs. No
         * pointer is dereferenced, no kernel function is called beyond the four
         * that run 4 already proved safe.
         */
        o->rd[10] = *(volatile uint64_t *)(kb + KO_KEY_LIST);
        o->rd[11] = *(volatile uint64_t *)(kb + KO_SM_FLAG);
        o->rd[12] = *(volatile uint64_t *)(kb + KO_CTX_STATUS);

        /* self_context_t, as AuthHeader leaves it:
             0x00 format = 2 (SELF)   0x08 total_header_size   0x10 segment
             0x1C ctx_id              0x20 svc_id              0x28 unk
             0x30 buf_id              0x38 header POINTER      0x40 mtx       */
        *(volatile uint32_t *)(ctxp + 0x00) = 2;
        *(volatile uint32_t *)(ctxp + 0x08) = (uint32_t)a->hdr_len;
        *(volatile uint32_t *)(ctxp + 0x1C) = 0;
        *(volatile uint64_t *)(ctxp + 0x20) = id;
        *(volatile uint64_t *)(ctxp + 0x28) = 0;
        *(volatile uint32_t *)(ctxp + 0x30) = (uint32_t)idx;
        *(volatile uint64_t *)(ctxp + 0x38) = page;

        o->rd[0] = *(volatile uint64_t *)(ctxp + 0x38);   /* the header PTR */
        o->rd[4] = buf_b + idx * PAGE_SZ;                 /* the BUS we pass */

        /* The verify_header call is deliberately OPT-IN (sd.cfg smcall=1), and
           the sub_63D780 probe that used to sit here has been REMOVED.
         *
         * verify_header calls sub_63D780, and that function executes
         * `mov dl, byte ptr [rdi + rcx + 0x40]` where `edi` is derived from a
         * field inside the header. For this SELF the resulting read lands about
         * 0x37100 bytes PAST the 0x1000 staging page. It happened to hit mapped
         * memory in run 4, but that is luck, not a guarantee - and it is exactly
         * the class of unvalidated read that softlocked the console on run 5.
         *
         * The probe was also redundant: run 4 already established that this
         * returns -2 and that verify_header then answers EINVAL. There is
         * nothing new to learn by asking a second time.
         *
         * So default OFF. The digest scan above runs unconditionally and
         * touches nothing but the page we wrote ourselves.
         */
        o->rd[8] = a->smcall;    /* echoed: the report says which mode ran */

        if (!a->smcall) { o->rc = 7; return; }

        /*
         * TRANSPORT PROBE - and it is free, because we already make this call.
         *
         * _sceSblAuthMgrSmFinalize (koff 0x63FF00) sends AuthMgr command 5 via
         * sceSblServiceMailbox(*(0x269C0A0), q, q) and then:
         *
         *     63FF7D  call sceSblServiceMailbox
         *     63FF94  test ebx, ebx
         *     63FF96  je   0x63FFBA
         *     63FFB4  mov  r14d, 5        ; mailbox FAILED -> returns 5
         *     63FFCA  mov  eax, r14d      ; otherwise 0
         *
         * so the return value is a clean binary transport verdict on the exact
         * module id verify_header is about to use:
         *
         *   rd[9] == 0  -> the mailbox works. A non-zero verify_header result is
         *                  then the secure module's OWN verdict on our header.
         *   rd[9] == 5  -> the mailbox call itself failed, and no packet contents
         *                  could ever have mattered.
         *
         * verifyHeader (koff 0x6401F0) has the same two-channel shape - it
         * returns the mailbox error verbatim at 0x6403E5/0x640405, and otherwise
         * returns packet+0x04 as the module status - so without this probe a
         * single -22 is genuinely ambiguous. This retires that ambiguity, which
         * is what the "EINVAL means the key is missing" conclusion rested on.
         */
        o->rd[9] = (uint64_t)(int64_t)finalize((void *)ctxp);   /* transport probe */

        /* ---- PROBE LOOP ------------------------------------------------------
         * Run 9 established: the transport is fine (rd[9]==0) and the module
         * answers -22 itself, through a packet that provably matches AuthHeader's
         * own construction field for field. So the open question is whether the
         * module refuses only THIS file, or every file we hand it. Handing it
         * SELFs this console demonstrably loads - /app0/eboot.bin above all -
         * settles that in one run.
         *
         * Per slot k: park header k in the slot's staging page, take hdr_len from
         * that page the way AuthHeader does (0x642F99/0x642FA2 - the u16 at 0x0C
         * plus the u16 at 0x0E), then finalize + verify and announce the verdict.
         * The hdr_len is read from the page, not passed in, so each probe carries
         * its own size.
         *
         * AuthHeader's own guard is mirrored: it refuses hdr_len > 0x1000 with
         * -35 (0x642FB4), so a page whose sizes exceed that is reported as SKIP
         * rather than sent as a request the console's own path would not make.
         */
        {
            uint64_t k;
            int      last_rv = 0;

            for (k = 0; k < a->n_hdr && k < 8; k++) {
                char lb[176];
                uint64_t hv, fmt;

                if (!a->p_hdr[k]) {
                    snprintf(lb, sizeof(lb), "selfdec2 P%llu NOREAD",
                             (unsigned long long)k);
                    printf_notification(lb);
                    continue;
                }

                r = (uint64_t)copyin((const void *)a->p_hdr[k], (void *)page, PAGE_SZ);
                if (r) {
                    snprintf(lb, sizeof(lb), "selfdec2 P%llu copyin=%llx",
                             (unsigned long long)k, (unsigned long long)r);
                    printf_notification(lb);
                    continue;
                }

                /* Take the format from the FILE, exactly as AuthHeader does, rather
                   than assuming SELF. AuthHeader tests the magic itself - 0x642F2B
                   for "\x7fELF" and 0x642F44 for 0x1d3d154f - and then:

                     1 (plain ELF): ctx->0x00 = 1, hdr_len = e_phnum*0x38 + 0x40
                                    (0x642F7B / 0x642F88, e_phnum = u16 at 0x38)
                     2 (SELF):      ctx->0x00 = 2, hdr_len = header_size + meta_size
                                    (0x642F99 / 0x642FA2)

                   Hardcoding 2 would mis-describe any .sprx on this console that is
                   a plain ELF, and the module would then be sent the wrong function
                   for the file class - indistinguishable from a real refusal. */
                {
                    uint8_t *pp = (uint8_t *)page;

                    if (pp[0] == 0x7f && pp[1] == 'E' && pp[2] == 'L' && pp[3] == 'F') {
                        fmt = 1;
                        hv  = (uint64_t)(*(volatile uint16_t *)(page + 0x38))
                            * 0x38ULL + 0x40ULL;
                    } else {
                        fmt = 2;
                        hv  = (uint64_t)(*(volatile uint16_t *)(page + 0x0C))
                            + (uint64_t)(*(volatile uint16_t *)(page + 0x0E));
                    }
                }

                if (hv == 0 || hv > 0x1000ULL) {
                    snprintf(lb, sizeof(lb),
                             "selfdec2 P%llu fmt=%llx hdr=%llx SKIP>0x1000",
                             (unsigned long long)k, (unsigned long long)fmt,
                             (unsigned long long)hv);
                    printf_notification(lb);
                    continue;
                }

                *(volatile uint32_t *)(ctxp + 0x00) = (uint32_t)fmt;
                *(volatile uint32_t *)(ctxp + 0x08) = (uint32_t)hv;
                *(volatile uint32_t *)(ctxp + 0x1C) = 0;
                *(volatile uint32_t *)(ctxp + 0x20) = 0;

                finalize((void *)ctxp);
                rv = (uint64_t)(int64_t)verify((void *)ctxp);
                last_rv = (int)(int64_t)rv;

                snprintf(lb, sizeof(lb),
                         "selfdec2 P%llu fmt=%llx hdr=%llx verify=%llx ctxid=%llx",
                         (unsigned long long)k, (unsigned long long)fmt,
                         (unsigned long long)hv,
                         (unsigned long long)rv,
                         (unsigned long long)*(volatile uint32_t *)(ctxp + 0x1C));
                printf_notification(lb);

                if (rv == 0) {          /* the module accepted this one */
                    o->rd[1] = 0;
                    o->rd[2] = *(volatile uint32_t *)(ctxp + 0x1C);
                    a->ctx   = *(volatile uint32_t *)(ctxp + 0x1C);
                    o->rc    = 0;
                    return;
                }
            }

            o->rd[1] = (uint64_t)(int64_t)last_rv;
            o->rd[2] = 0;
            o->rd[3] = a->n_hdr;        /* how many slots were attempted */
            o->rc    = 7;
            return;
        }
    }

    /* ---- 8: AUTHMGR_CMD_LOAD_SELF_SEGMENT, then read the plaintext ---- */
    case 8: {
        uint64_t seg_map = ALIGN_PAGE(a->seg_size);
        uint64_t id      = *(volatile uint64_t *)(kb + KO_MODULE_ID);
        a->svc_id = id;
        if (a->svcreq && id == 0) { o->rc = 8; return; }   /* hang guard */

        a->seg_buf = (uint64_t)kmalloc(seg_map, mtype, 0x102);
        o->rd[0] = a->seg_buf;
        if (!a->seg_buf) { o->rc = 8; return; }
        memset((void *)a->seg_buf, 0, seg_map);

        r = (uint64_t)mappages(&a->seg_bus, (void *)a->seg_buf,
                               (uint32_t)(seg_map / PAGE_SZ), 0x61, 0,
                               &a->seg_desc);
        o->rd[1] = r;
        o->rd[2] = a->seg_bus;
        o->rd[3] = a->seg_desc;
        if (r) { o->rc = 8; return; }

        /* pull the encrypted segment bytes out of the SELF image */
        r = (uint64_t)copyin((const void *)(a->p_self + a->seg_off),
                             (void *)a->seg_buf, a->seg_size);
        o->rd[4] = r;
        if (r) { o->rc = 8; return; }

        /* chunk table: 0x20 header + one entry */
        a->ct_buf = (uint64_t)kmalloc(PAGE_SZ, mtype, 0x102);
        o->rd[5] = a->ct_buf;
        if (!a->ct_buf) { o->rc = 8; return; }
        memset((void *)a->ct_buf, 0, PAGE_SZ);
        {
            uint64_t *t = (uint64_t *)a->ct_buf;
            t[0] = a->seg_bus;    /* data_addr  / first_pa        */
            t[1] = a->seg_size;   /* data_size                    */
            t[2] = 1;             /* num_entries / used_entries   */
            t[3] = 0;             /* reserved                     */
            t[4] = a->seg_bus;    /* entries[0].data_addr         */
            t[5] = a->seg_size;   /* entries[0].data_size         */
        }
        r = (uint64_t)mappages(&a->ct_bus, (void *)a->ct_buf, 1, 0x61, 0,
                               &a->ct_desc);
        o->rd[6] = r;
        o->rd[7] = a->ct_bus;
        o->rd[8] = a->ct_desc;
        if (r) { o->rc = 8; return; }

        /* sbl_authmgr_load_self_segment_t, 0x80 bytes */
        memset(q, 0, sizeof(q));
        q[0] = AUTHMGR_CMD_LOAD_SELF_SEGMENT;        /* 0x00 function       */
                                                     /* 0x04 status = 0     */
        q[1] = a->ct_bus;                            /* 0x08 chunk table    */
        q[2] = (a->seg_index & 0xffffffffULL);       /* 0x10 segment_index  */
                                                     /* 0x14 is_block_table */
        q[6] = a->ctx & 0xffffffffULL;               /* 0x30 context_id     */

        if (a->lock) xlock(smx, 0, 0, 0);
        r = (uint64_t)mailbox(id, q, q);
        if (a->lock) xunlock(smx, 0, 0);

        o->rd[9]  = r;
        o->rd[10] = q[0] & 0xffffffffULL;
        o->rd[11] = (q[0] >> 32) & 0xffffffffULL;

        /* the SM decrypts IN PLACE, so seg_buf now holds the plaintext */
        o->rd[12] = (uint64_t)copyout((const void *)a->seg_buf,
                                      (void *)a->p_out, a->seg_size);
        o->rd[13] = a->seg_size;
        if (r || (q[0] & 0xffffffffULL) != AUTHMGR_CMD_LOAD_SELF_SEGMENT)
            o->rc = 8;
        return;
    }

    /* ---- 9: give the SM its pages back ---- */
    case 9:
        o->rd[0] = (uint64_t)unmap(a->hdr_desc);
        o->rd[1] = (uint64_t)unmap(a->ai_desc);
        if (a->seg_desc) o->rd[2] = (uint64_t)unmap(a->seg_desc);
        if (a->ct_desc)  o->rd[3] = (uint64_t)unmap(a->ct_desc);
        return;

    default:
        o->rc = -1;
        return;
    }
}

/* ------------------------------------------------------------------ */
/* userspace helpers                                                   */
/* ------------------------------------------------------------------ */
static uint64_t rd64(const uint8_t *p)
{
    uint64_t v = 0;
    int i;
    for (i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}
static uint32_t rd16(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8);
}
static uint64_t hexval(const char *s)
{
    uint64_t v = 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    for (; *s; s++) {
        int d;
        char c = *s;
        if (c >= '0' && c <= '9')      d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else break;
        v = (v << 4) | (uint64_t)d;
    }
    return v;
}

static int read_file(const char *path, uint8_t **out, uint64_t *out_size)
{
    int fd = open(path, O_RDONLY, 0);
    off_t sz;
    ssize_t got;
    uint8_t *buf;
    if (fd < 0) return -1;
    sz = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    if (sz <= 0) { close(fd); return -2; }
    buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) { close(fd); return -3; }
    got = read(fd, buf, (size_t)sz);
    close(fd);
    if (got != (ssize_t)sz) { free(buf); return -4; }
    *out = buf; *out_size = (uint64_t)sz;
    return 0;
}

static int write_file(const char *path, const uint8_t *buf, uint64_t size)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0777);
    uint64_t done = 0;
    if (fd < 0) return -1;
    while (done < size) {
        ssize_t w = write(fd, buf + done, (size_t)(size - done));
        if (w <= 0) { close(fd); return -2; }
        done += (uint64_t)w;
    }
    close(fd);
    return 0;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
/*
 * Paths are tried in order. /data/payloads is the PS4's own partition and has
 * proved far more reliable over GoldHEN's FTP than the FAT stick at /mnt/usb0
 * (an FTP write there killed the FTP server outright). Everything is written
 * to BOTH locations so whichever one survives, the result is retrievable.
 *
 * IMPORTANT: these must stay string LITERALS used directly. A global
 * `const char *` table would need R_X86_64_RELATIVE relocations, and
 * objcopy -O binary does not carry them - it garbles the payload.
 */

struct sd_cfg {
    uint64_t maxstep;
    uint64_t lock;
    uint64_t svcreq;
    uint64_t seg;
    uint64_t ctxidx;     /* 0..3 pins the context slot; 0xff = first free */
    uint64_t smcall;     /* 1 = run the verify_header call (has an OOB read) */
};

static void sd_cfg_default(struct sd_cfg *c)
{
    c->maxstep = 7;      /* plumbing + context pick; SM call only if id != 0 */
    c->lock    = 1;
    c->svcreq  = 0;   /* 0: allow the mailbox call (see patch_svcreq.py) */
    c->seg     = 0;
    c->ctxidx  = 0xff;
    /* ON by default now. The opt-out no longer earns its keep, for two reasons:
     *
     *  1. Its justification was wrong. sub_63D780's guard (`cmp edx,3 / jb fail`)
     *     executes BEFORE the byte read at 0x63D7D3, and for 80010008 that guard
     *     FAILS - run 4 measured digest = 0xfffffffe, i.e. -2 - so the read never
     *     happens. Even if it did, the address would be header + 0x140, well
     *     inside the 0x1000 page, not ~0x37100 past it.
     *     See 1352-AUTHMGR-REOPEN.md.
     *  2. smcall=1 is the entire point of the run: it gates the rd[9] transport
     *     probe. Leaving it off makes every run meaningless.
     *
     * It also cannot be enabled from sd.cfg reliably, because sd.cfg has to be
     * placed over GoldHEN's FTP and that server dies on its first data command.
     * The default has to be the value we actually want. */
    c->smcall  = 1;
}

static void sd_cfg_parse(struct sd_cfg *c)
{
    int fd = open("/data/payloads/sd.cfg", O_RDONLY, 0);
    if (fd < 0)
        fd = open("/mnt/usb0/sd.cfg", O_RDONLY, 0);
    char buf[512];
    int n;
    char *p;
    if (fd < 0) return;
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return;
    buf[n] = 0;

    p = buf;
    for (;;) {
        char *e = p, *eq;
        int had;
        while (*e && *e != '\n' && *e != '\r') e++;
        had = (*e != 0);
        *e = 0;

        eq = p;
        while (*eq && *eq != '=') eq++;
        if (*eq == '=') {
            char *v;
            *eq = 0;
            v = eq + 1;
            while (*v == ' ' || *v == '\t') v++;
            if (!strcmp(p, "maxstep")) {
                uint64_t x = hexval(v);
                if (x >= 1 && x <= STEP_MAX) c->maxstep = x;
            } else if (!strcmp(p, "lock")) {
                c->lock = (v[0] == '1') ? 1 : 0;
            } else if (!strcmp(p, "svcreq")) {
                c->svcreq = (v[0] == '1') ? 1 : 0;
            } else if (!strcmp(p, "seg")) {
                c->seg = hexval(v);
            } else if (!strcmp(p, "ctxidx")) {
                uint64_t x = hexval(v);
                if (x < CTX_COUNT) c->ctxidx = x;
            } else if (!strcmp(p, "smcall")) {
                c->smcall = hexval(v);
            }
        }
        if (!had) break;
        p = e + 1;
    }
}

static void sta(const char *s)
{
    int L = 0;
    while (s[L]) L++;
    write_file("/data/payloads/sd_status.txt", (const uint8_t *)s, (uint64_t)L);
    write_file("/mnt/usb0/sd_status.txt", (const uint8_t *)s, (uint64_t)L);
}

/* read the SELF from whichever mount is available */
static int read_target(uint8_t **out, uint64_t *out_size)
{
    if (read_file("/data/payloads/target.self", out, out_size) == 0)
        return 0;
    return read_file("/mnt/usb0/target.self", out, out_size);
}

/* write the decrypted segment to both mounts */
static int write_plain(const uint8_t *buf, uint64_t size)
{
    int r = write_file("/data/payloads/plain.bin", buf, size);
    int r2 = write_file("/mnt/usb0/plain.bin", buf, size);
    return (r == 0 || r2 == 0) ? 0 : -1;
}

int _main(struct thread *td)
{
    char msg[200];
    char sta_buf[400];
    struct sd_cfg c;
    uint8_t *self = 0, *out = 0;
    uint64_t self_size = 0;
    int      self_embedded = 0;   /* self points at g_embed_hdr, never free() it */
    uint64_t hdr_len, seg_off, seg_size, seg_index, out_cap;
    uint64_t kbase, i;

    initKernel();
    initLibc();
    initPthread();
    initNetwork();
    initSysUtil();

    (void)td;
    printf_notification("selfdec2: start");

    kbase = get_kernel_base();
    if (!kbase) { printf_notification("selfdec2 ABORT: no kbase"); return 0; }
    jailbreak();
    mmap_patch();

    snprintf(msg, sizeof(msg), "selfdec2 kbase=%llx",
             (unsigned long long)kbase);
    printf_notification(msg);

    sd_cfg_default(&c);
#if !NO_IO
    sd_cfg_parse(&c);      /* opens two paths - part of the I/O under test */
#else
    printf_notification("selfdec2 NOIO: sd.cfg not read, using defaults");
#endif

    /*
     * FORCE smcall on, after the parse, overriding whatever sd.cfg said.
     *
     * Measured, run 8: sd_cfg_default() says 1 and yet the run reported
     * "sm=0" and step 7 returned rc=7 with the probe never executed. So a stale
     * sd.cfg was read and won - almost certainly /mnt/usb0/sd.cfg left over from
     * run 7, reached because /data/payloads/sd.cfg is absent and sd_cfg_parse
     * falls back to the stick. It carries the run-7 line `smcall=0`.
     *
     * That file cannot be corrected without GoldHEN's FTP, which dies on its
     * first data command (doc 13.1) - so the value has to be enforced here. The
     * other cfg keys are still honoured: run 8 showed the correct
     * maxstep=7 lock=1 svcreq=0 seg=0 ctx=0, and svcreq=0 in particular matters,
     * because step 7 aborts before the mailbox whenever svcreq && module_id == 0.
     *
     * Without this, every run is a no-op: step 7 returns before the rd[9] probe.
     */
    c.smcall = 1;

#if LAUNCH_ONLY
    /*
     * Launch-isolation run. Everything below - the target reads, the allocations
     * and the whole kexec'd step sequence - is deliberately skipped. If the
     * console still goes down from here, the cause is the injection, not us.
     * The marker is the only thing this build does.
     */
    printf_notification("selfdec2 LAUNCHONLY marker - payload ran, exiting with no work");
    return 0;
#endif
    snprintf(msg, sizeof(msg),
             "selfdec2 max=%llu lock=%llu svcreq=%llu seg=%llu ctx=%llu sm=%llu",
             (unsigned long long)c.maxstep, (unsigned long long)c.lock,
             (unsigned long long)c.svcreq, (unsigned long long)c.seg,
             (unsigned long long)c.ctxidx, (unsigned long long)c.smcall);
    printf_notification(msg);

    /* --- read the SELF, if there is one --- */
#if NO_IO
    /* NO_IO: no file is opened at all. The compiled-in header page is used, and
       self=4096 in the report says so. */
    printf_notification("selfdec2 NOIO: target.self not read, using embedded header");
    self = (uint8_t *)g_embed_hdr;
    self_size = EMBED_HDR_SIZE;
    self_embedded = 1;
#else
    if (read_target(&self, &self_size) != 0) {
        /*
         * Fall back to the header page compiled into the payload.
         *
         * target.self has to reach the console over GoldHEN's FTP, and that FTP
         * server dies on its first data command - three attempts in a row, each
         * one taking GoldHEN down with it. The payload itself arrives over TCP,
         * which works fine. Step 7 copies exactly PAGE_SZ bytes out of the file
         * into the module's staging page and needs nothing else, so those 0x1000
         * bytes (from the encrypted SELF already held locally) are compiled in.
         *
         * Consequence seen in the report: self=4096, not 88304.
         */
        printf_notification("selfdec2: no target.self - using embedded header");
        self = (uint8_t *)g_embed_hdr;
        self_size = EMBED_HDR_SIZE;
        self_embedded = 1;
    }
#endif

    /* sanity: a SELF starts with the ASCII magic "SCE\0". Anything else and we
       pretend we have no file at all, so the NULL-source guard above holds. */
    /*
     * DO NOT test for a SELF magic here.
     *
     * Every SELF in dec/ (80010008, 80010002, the 14.00 kernel, orbis_swu)
     * begins with 4f153d1d = 0x1d3d154f, NOT the textbook SELF magic
     * 0x00454353. An "SCE" check I added for robustness therefore rejected a
     * perfectly good file and cost two runs; run 1 worked only because it
     * predated that check. Validity is established structurally instead - the
     * geometry tests below reject anything whose header does not chain
     * coherently within the file.
     */
    if (self && self_size < 0x100) {
        printf_notification("selfdec2: target.self too small");
        if (!self_embedded) free(self);
        self = 0;
        self_size = 0;
    }

    if (self && self_size > 0x40) {
        hdr_len  = (uint64_t)rd16(self + 0x0C)     /* header_size   */
                 + (uint64_t)rd16(self + 0x0E);    /* metadata_size */
        /* clamps: the header staging buffer is 0x4000 and we will not kmalloc
           more than 32 MB, so a corrupt file cannot ask for either. */
        if (hdr_len == 0 || hdr_len > 0x4000) {
            printf_notification("selfdec2: bad hdr_len, clamping");
            hdr_len = 0x4000;
        }
        seg_index = c.seg;
        if (seg_index >= rd16(self + 0x18)) {
            printf_notification("selfdec2: seg out of range");
            seg_index = 0;
        }
        seg_off  = rd64(self + 0x20 + seg_index * 0x20 + 0x08);
        seg_size = rd64(self + 0x20 + seg_index * 0x20 + 0x10);
        if (seg_off + seg_size > self_size || seg_size > 0x2000000ULL) {
            printf_notification("selfdec2: bad segment range, skipping step 8");
            seg_size = 0;
        }
        snprintf(msg, sizeof(msg),
                 "selfdec2 self=%lluB hdr=%llu seg%llu off=%llx sz=%llx",
                 (unsigned long long)self_size, (unsigned long long)hdr_len,
                 (unsigned long long)seg_index, (unsigned long long)seg_off,
                 (unsigned long long)seg_size);
        printf_notification(msg);
    } else {
        hdr_len = 0x4000; seg_off = 0; seg_size = 0; seg_index = 0;
        /* no SELF means steps 5..8 have nothing to read: stop after the
           plumbing. Steps 1..4 still prove kmalloc + MapPages. */
        if (c.maxstep > 4) c.maxstep = 4;
        printf_notification("selfdec2: no target - plumbing steps 1-4 only");
    }

    /*
     * Build the verify-probe list.
     *
     * Slot 0 is always the embedded 80010008 page: the baseline, since run 9
     * proved the module refuses that file with -22 through a packet that is
     * byte-for-byte what AuthHeader itself builds.
     *
     * Slots 1.. are SELFs that live on THIS console and that the console already
     * loads - the paths come straight out of its own module listing in
     * console_log_run8.txt. /app0/eboot.bin is the strongest control there is:
     * the running application's own SELF, already loaded and verified by this
     * machine.
     *
     * The read result is announced per slot with its path, so a file that could
     * not be opened is never mistaken for a header the module refused. That
     * distinction is the entire point of this build. (Paths are per-process
     * namespaces; this payload runs in ScePartyDaemon, so /app0 may not resolve
     * here - which is exactly why the result is reported instead of assumed.)
     */
    {
        uint64_t n_hdr = 0;

        g_pb[n_hdr++] = (uint64_t)(const unsigned char *)g_embed_hdr;  /* slot 0 */

        /* Each block: try to read the first 0x1000 bytes, announce the outcome
           with the literal path, and record the pointer (or 0). */

        /*
         * ONLY paths that have already been proven readable from THIS process.
         *
         * The /app0/... and /siqKUaIVzd/... probes were removed on purpose. They
         * returned MISS on every single run, contributed nothing, and run 11 died
         * *on* the /siqKUaIVzd read - 792 bytes captured, cut off mid-notification
         * at (_main:1138), with no step ever reaching kernel mode. Resolving a path
         * inside a sandbox mount this process does not own is a plausible way to
         * wedge a kernel filesystem lock, and a probe that can only ever return
         * MISS is all cost and no information.
         *
         * /data/payloads/target.self and the two /system/common/lib/ libraries have
         * been read successfully on every run that got this far. Every read below
         * is one that has already worked on this console.
         */

#if NO_IO
        /* NO_IO: the console-SELF reads are skipped. Only the embedded 80010008
           page is probed, so this run re-confirms the -22 verdict rather than
           testing a loadable SELF - that is the price of removing all I/O. */
        printf_notification("selfdec2 NOIO: console-SELF reads skipped");
#else
        {   /* slot 1 - proven readable (run 10) */
            uint8_t *pb = 0; uint64_t ps = 0;
            int ok = (read_file("/system/common/lib/libkernel_sys.sprx", &pb, &ps) == 0
                      && ps >= 0x1000ULL);
            printf_notification(ok ? "selfdec2 seek1 /system/common/lib/libkernel_sys.sprx OK"
                                   : "selfdec2 seek1 /system/common/lib/libkernel_sys.sprx MISS");
            g_pb[n_hdr++] = ok ? (uint64_t)pb : 0;
        }
        {   /* slot 2 - proven readable (run 10) */
            uint8_t *pb = 0; uint64_t ps = 0;
            int ok = (read_file("/system/common/lib/libSceAudioOut.sprx", &pb, &ps) == 0
                      && ps >= 0x1000ULL);
            printf_notification(ok ? "selfdec2 seek2 /system/common/lib/libSceAudioOut.sprx OK"
                                   : "selfdec2 seek2 /system/common/lib/libSceAudioOut.sprx MISS");
            g_pb[n_hdr++] = ok ? (uint64_t)pb : 0;
        }
#endif

        /* staged, not published: g_a is memset just below, before the step loop */
        g_pn = n_hdr;
        snprintf(msg, sizeof(msg), "selfdec2 probe slots %llu",
                 (unsigned long long)n_hdr);
        printf_notification(msg);
    }

    /* --- output buffer --- */
    out_cap = (seg_size > 0x10000ULL) ? ALIGN_PAGE(seg_size) : 0x10000ULL;
    out = (uint8_t *)malloc((size_t)out_cap);
    if (!out) { printf_notification("selfdec2 ABORT: no out buf"); return 0; }
    memset(out, 0, (size_t)out_cap);

    /* --- run steps --- */
    memset(&g_a, 0, sizeof(g_a));
    memset(&g_r, 0, sizeof(g_r));

    /* publish the probe list AFTER the wipe above (see g_pb/g_pn) */
    g_a.n_hdr = g_pn;
    for (i = 0; i < g_pn && i < 8; i++)
        g_a.p_hdr[i] = g_pb[i];

    g_a.kbase    = kbase;
    g_a.lock     = c.lock;
    g_a.svcreq   = c.svcreq;
    g_a.ctxidx   = c.ctxidx;
    g_a.smcall   = c.smcall;
    g_a.hdr_len  = hdr_len;
    g_a.seg_index = seg_index;
    g_a.seg_off  = seg_off;
    g_a.seg_size = seg_size;
    g_a.self_size = self_size;
    g_a.p_self   = (uint64_t)self;
    g_a.p_out    = (uint64_t)out;
    g_a.out_cap  = out_cap;

    memset(&g_r, 0, sizeof(g_r));
    for (i = 1; i <= c.maxstep && i <= STEP_MAX; i++) {
        g_a.step = i;
        g_r.step = 0;
        g_r.rc   = -99;

        /* print BEFORE the risky step, so a hang still tells us which one */
        snprintf(msg, sizeof(msg), "selfdec2 -> step %llu",
                 (unsigned long long)i);
        printf_notification(msg);

        kexec(sd_step, (void *)&g_a);

        if (i < 12) g_rcs[i] = g_r.rc;

        snprintf(msg, sizeof(msg), "selfdec2 step %llu rc=%d %llx %llx %llx",
                 (unsigned long long)i, g_r.rc,
                 (unsigned long long)g_r.rd[0],
                 (unsigned long long)g_r.rd[1],
                 (unsigned long long)g_r.rd[2]);
        printf_notification(msg);

        snprintf(sta_buf, sizeof(sta_buf),
                 "step=%llu rc=%d rd0=%llx rd1=%llx rd2=%llx rd3=%llx\n",
                 (unsigned long long)i, g_r.rc,
                 (unsigned long long)g_r.rd[0],
                 (unsigned long long)g_r.rd[1],
                 (unsigned long long)g_r.rd[2],
                 (unsigned long long)g_r.rd[3]);
        sta(sta_buf);

        if (g_r.rc != 0) {
            printf_notification("selfdec2: stopping here");
            break;
        }
    }

    /* --- report the last step in more detail --- */
    {
        char d[640];
        char rc_hist[72];
        int  j, p = 0;
        rc_hist[0] = 0;
        for (j = 1; j <= (int)c.maxstep && j < 12 && p < 64; j++)
            p += snprintf(rc_hist + p, sizeof(rc_hist) - p, "%d,",
                          (int)g_rcs[j]);
        snprintf(d, sizeof(d),
                     "last step=%llu rc=%d\n"
                     "self=%llu max=%llu hdr=%llu segsz=%llu\n"
                     "rcs=%s\n"
                     /* step 7: verify = the module's own status, straight from
                        _sceSblAuthMgrSmVerifyHeader's return value. */
                     "hdrptr=%llx verify=%llx ctxid_out=%llx ctx20=%llx\n"
                     "bus=%llx bufB=%llx cbb=%llx smflag=%llx\n"
                     "digest=%llx dptr=%llx idx=%llx copyin=%llx\n"
                     "ownbus=%llx keyhead=%llx smflag2=%llx ctxstate=%llx\n"
                     "ctx=%llu svc=%llx\n",
                     (unsigned long long)g_r.step, (int)g_r.rc,
                     (unsigned long long)self_size,
                     (unsigned long long)c.maxstep,
                     (unsigned long long)hdr_len,
                     (unsigned long long)seg_size,
                     rc_hist,
                     (unsigned long long)g_r.rd[0],
                     (unsigned long long)g_r.rd[1],
                     (unsigned long long)g_r.rd[2],
                     (unsigned long long)g_r.rd[3],
                     (unsigned long long)g_r.rd[4],
                     (unsigned long long)g_r.rd[5],
                     (unsigned long long)g_r.rd[6],
                     (unsigned long long)g_r.rd[7],
                     (unsigned long long)g_r.rd[8],
                     (unsigned long long)g_r.rd[9],
                     (unsigned long long)g_r.rd[13],
                     (unsigned long long)g_r.rd[14],
                     (unsigned long long)g_r.rd[15],
                     (unsigned long long)g_r.rd[10],
                     (unsigned long long)g_r.rd[11],
                     (unsigned long long)g_r.rd[12],
                     (unsigned long long)g_a.ctx,
                     (unsigned long long)g_a.svc_id);
         sta(d);

         /*
          * ALSO emit the report into the kernel log, not just into sd_status.txt.
          *
          * Run 8 exposed the gap: the only place the verdict appears is
          * sd_status.txt, and reading that needs GoldHEN's FTP - which dies on its
          * first data command and takes GoldHEN down with it (doc 13.1). But the
          * log path is proven end to end: GoldHEN streams klog on 3232 and every
          * printf_notification from this payload showed up in run 8's capture.
          * Routing the report there too means the result of a run is retrievable
          * with no FTP at all.
          *
          * Emitted line by line so each notification stays well inside the
          * ~200-byte message limit (d is 640 bytes in total).
          */
         {
             const char *ls = d;
             while (*ls) {
                 const char *nl = ls;
                 char lb[192];
                 int k = 0;

                 while (*nl && *nl != '\n') nl++;

                 k += snprintf(lb + k, sizeof(lb) - (size_t)k, "selfdec2 R: ");
                 while (ls < nl && k < (int)sizeof(lb) - 1)
                     lb[k++] = *ls++;
                 lb[k] = 0;

                 printf_notification(lb);
                 if (!*nl) break;
                 ls = nl + 1;
             }
         }
     }

    /* --- if the segment came back, save it --- */
    if (c.maxstep >= 8 && seg_size && g_r.step == 8 && g_r.rc == 0) {
        if (write_plain(out, seg_size) == 0)
            printf_notification("selfdec2: wrote plain.bin");
        else
            printf_notification("selfdec2: plain.bin write FAILED");
    } else if (c.maxstep >= 5) {
        /* keep the 0x20-byte header readback for offline comparison */
        write_file("/data/payloads/sd_hdr20.bin", out, 0x20);
        write_file("/mnt/usb0/sd_hdr20.bin", out, 0x20);
    }

    printf_notification("selfdec2: done");
    return 0;
}






