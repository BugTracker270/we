/*
 * kmemdump v10 — size ladder first, then a small targeted dump.
 *
 * WHAT v9 PROVED (all nine probe reads returned r=0)
 * --------------------------------------------------
 *   P0 1520000 "ORBISS" Sony ORBIS tag        P5 269c000 0xffffc18715c02c00
 *   P1 1521000 kbase+0x771204 (kernel ptr)    P6 269c0a0 0                 (SM handle)
 *   P2 1b265e8 0                              P7 269c140 2                 (ctx state)
 *   P3 1b266e8 0                              P8 2834ae8 4
 *   P4 2000000 0
 *
 * So PT_LOAD 1 (.data/.bss) is readable at every probed offset. The address was
 * never the problem: v7's 0-byte kmem_img.bin, combined with this, means the
 * 128 KiB copyout was what killed the console. Size, not address.
 *
 * P7 is also the first hardware confirmation of the offset table:
 * KO_1352_AUTHMGR_CTX_TABLE reads 2 at +0x00, exactly the CTX_OFF_STATE value
 * that sceSblAuthMgrIsLoadable requires (1 or 2). P6=0 matches "SM handle is 0
 * until started".
 *
 * WHAT v10 DOES
 * -------------
 *   1. LADDER: reads the SAME address (0x1520000) at 8, 64, 256, 1024, 4096
 *      bytes, reporting r for each, stopping at the first failure. This finds
 *      the largest copyout this console tolerates instead of me guessing again.
 *      The chosen chunk is the largest size that succeeded, capped at 4096.
 *   2. DUMP: walks the window with that chunk. The default window is deliberately
 *      TINY — 128 KiB around the AuthMgr/SBL structures — because that region is
 *      the most information-dense thing we know about and it costs ~32 reads.
 *      start/end/chunk can be overridden from /mnt/usb0/kmem.cfg to widen it
 *      later without a rebuild.
 *   3. Status every 16 chunks, so a failure still tells us the exact offset.
 *
 * Still no kernel calls. Still only get_memory_dump().
 */

#include "ps4.h"
#include "offsets_1352.h"

#define CFG_FILE  "/mnt/usb0/kmem.cfg"
#define OUT_FILE  "/mnt/usb0/kmem_img.bin"
#define IDX_FILE  "/mnt/usb0/kmem_img.txt"
#define STA_FILE  "/mnt/usb0/kmem_status.txt"

/* default window: AuthMgr + SBL structure block, 128 KiB */
#define DEF_START 0x02680000ULL
#define DEF_END   0x026A0000ULL
#define DEF_CHUNK 0x00001000ULL
#define MAX_CHUNK 0x00040000ULL

/* the ladder — same address, growing copyout, smallest first */
static const uint64_t ladder[5] = { 8ULL, 64ULL, 256ULL, 1024ULL, 4096ULL };

static uint64_t g_kbase = 0;

static int kread(uint64_t kaddr, void *out, size_t size)
{
    return get_memory_dump(kaddr, (uint64_t *)out, size);
}

static ssize_t write_all(int fd, const uint8_t *buf, uint64_t n)
{
    uint64_t done = 0;
    while (done < n) {
        ssize_t w = write(fd, buf + done, (size_t)(n - done));
        if (w <= 0)
            return -1;
        done += (uint64_t)w;
    }
    return (ssize_t)done;
}

static void status(int fd, const char *s, int len)
{
    if (fd < 0)
        return;
    lseek(fd, 0, SEEK_SET);
    write(fd, s, (size_t)len);
}

static uint64_t rd_hex(const char *s)
{
    uint64_t v = 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        s += 2;
    for (; *s; s++) {
        char c = *s;
        int d;
        if (c >= '0' && c <= '9')       d = c - '0';
        else if (c >= 'a' && c <= 'f')  d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')  d = c - 'A' + 10;
        else break;
        v = (v << 4) | (uint64_t)d;
    }
    return v;
}

static void cfg_line(char *line, uint64_t *start, uint64_t *end, uint64_t *chunk,
                     int *absm)
{
    char *eq = line;
    while (*eq && *eq != '=')
        eq++;
    if (*eq != '=')
        return;
    *eq = 0;

    char *k = line;
    char *v = eq + 1;
    while (*v == ' ' || *v == '\t')
        v++;

    if (!strcmp(k, "start"))
        *start = rd_hex(v);
    else if (!strcmp(k, "end"))
        *end = rd_hex(v);
    else if (!strcmp(k, "chunk")) {
        uint64_t c = rd_hex(v);
        if (c >= 8 && c <= MAX_CHUNK)
            *chunk = c;
    } else if (!strcmp(k, "abs")) {
        /* abs=1 => start/end are ABSOLUTE kernel VAs, not kbase-relative.
           Needed because the AuthMgr's own state points into the 0xffffc187..
           arena, which is nowhere near the kernel image. */
        *absm = (v[0] == '1');
    }
}

static void parse_cfg(uint64_t *start, uint64_t *end, uint64_t *chunk, int *absm)
{
    int fd = open(CFG_FILE, O_RDONLY, 0);
    char buf[512];
    int n;
    char *p;

    if (fd < 0)
        return;
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return;
    buf[n] = 0;

    p = buf;
    for (;;) {
        char *e = p;
        int had;
        while (*e && *e != '\n' && *e != '\r')
            e++;
        had = (*e != 0);
        *e = 0;
        cfg_line(p, start, end, chunk, absm);
        if (!had)
            break;
        p = e + 1;
    }
}

int _main(struct thread *td)
{
    char msg[160];
    uint64_t start = DEF_START, end = DEF_END, chunk = DEF_CHUNK;
    uint64_t safe = 0, addrbase;
    uint8_t *lbuf;
    int absm = 0;
    int idf, i, r;

    initKernel();
    initLibc();
    initPthread();
    initNetwork();
    initSysUtil();

    printf_notification("KMEMv10: start");

    g_kbase = get_kernel_base();
    if (!g_kbase) {
        printf_notification("KMEMv10 ABORT: no kernel base");
        return 0;
    }
    jailbreak();
    mmap_patch();

    snprintf(msg, sizeof(msg), "KMEMv10 kbase=%llx", (unsigned long long)g_kbase);
    printf_notification(msg);

    idf = open(IDX_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (idf >= 0) {
        char h[160];
        int L = snprintf(h, sizeof(h), "kbase=0x%llx\n",
                         (unsigned long long)g_kbase);
        write_all(idf, (const uint8_t *)h, (uint64_t)L);
    }

    /* ---- LADDER: find the largest copyout this console tolerates ---- */
    lbuf = (uint8_t *)malloc(MAX_CHUNK);
    if (!lbuf) {
        printf_notification("KMEMv10 ABORT: no ladder buffer");
        return 0;
    }
    memset(lbuf, 0, MAX_CHUNK);

    for (i = 0; i < 5; i++) {
        uint64_t sz = ladder[i];
        uint64_t w = 0;
        r = kread(g_kbase + 0x1520000ULL, lbuf, (size_t)sz);
        if (r == 0 && sz >= 8)
            memcpy(&w, lbuf, 8);
        snprintf(msg, sizeof(msg), "KMEMv10 L%d sz=%llu r=%d v=%llx",
                 i, (unsigned long long)sz, r, (unsigned long long)w);
        printf_notification(msg);
        if (idf >= 0) {
            char line[160];
            int L = snprintf(line, sizeof(line),
                             "L%d size=%llu r=%d v=0x%llx\n", i,
                             (unsigned long long)sz, r, (unsigned long long)w);
            write_all(idf, (const uint8_t *)line, (uint64_t)L);
        }
        if (r != 0)
            break;
        safe = sz;
    }
    free(lbuf);

    if (safe == 0) {
        snprintf(msg, sizeof(msg), "KMEMv10 ABORT: even 8 bytes failed r=%d", r);
        printf_notification(msg);
        if (idf >= 0)
            close(idf);
        return 0;
    }

    snprintf(msg, sizeof(msg), "KMEMv10 ladder max=%llu", (unsigned long long)safe);
    printf_notification(msg);

    /* ---- DUMP ---- */
    parse_cfg(&start, &end, &chunk, &absm);
    if (chunk > safe)
        chunk = safe;                 /* never exceed what the ladder proved */
    if (chunk < 8)
        chunk = 8;
    if (end <= start)
        end = start + chunk;

    addrbase = absm ? 0ULL : g_kbase;

    snprintf(msg, sizeof(msg), "KMEMv10 DUMP %s%llx-%llx step %llx",
             absm ? "abs " : "",
             (unsigned long long)(start + addrbase),
             (unsigned long long)(end + addrbase),
             (unsigned long long)chunk);
    printf_notification(msg);

    {
        uint8_t *buf = (uint8_t *)malloc((size_t)chunk);
        int fd, sfd;
        uint64_t off, done = 0, stopped = 0;
        int fails = 0, chunks = 0;

        if (!buf) {
            printf_notification("KMEMv10 ABORT: no buffer");
            if (idf >= 0)
                close(idf);
            return 0;
        }
        memset(buf, 0, (size_t)chunk);

        fd = open(OUT_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0777);
        if (fd < 0) {
            printf_notification("KMEMv10 ABORT: cannot open output");
            free(buf);
            if (idf >= 0)
                close(idf);
            return 0;
        }
        sfd = open(STA_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0777);

        for (off = start; off < end; off += chunk) {
            uint64_t n = end - off;
            if (n > chunk)
                n = chunk;

            if (kread(addrbase + off, buf, (size_t)n) != 0) {
                fails++;
                stopped = off;
                break;
            }
            if (write_all(fd, buf, n) < 0) {
                fails = -1;
                stopped = off;
                break;
            }
            done += n;
            chunks++;

            if ((chunks & 15) == 0) {
                int L = snprintf(msg, sizeof(msg),
                                 "off=0x%llx done=%lluB chunks=%d\n",
                                 (unsigned long long)(off + n),
                                 (unsigned long long)done, chunks);
                status(sfd, msg, L);
            }
            if (chunks < 8 || (chunks & 255) == 0) {
                snprintf(msg, sizeof(msg), "KMEMv10 %llx %lluB",
                         (unsigned long long)(off + addrbase),
                         (unsigned long long)done);
                printf_notification(msg);
            }
        }
        close(fd);
        if (sfd >= 0)
            close(sfd);

        if (idf >= 0) {
            char s[512];
            int L = snprintf(s, sizeof(s),
                "start=0x%llx\nend=0x%llx\nchunk=0x%llx\nstopped_at=0x%llx\n"
                "bytes=%llu\nchunks=%d\nfails=%d\n",
                (unsigned long long)start, (unsigned long long)end,
                (unsigned long long)chunk, (unsigned long long)stopped,
                (unsigned long long)done, chunks, fails);
            write_all(idf, (const uint8_t *)s, (uint64_t)L);
            close(idf);
        }

        snprintf(msg, sizeof(msg), "KMEMv10 done %lluB stop=%llx",
                 (unsigned long long)done, (unsigned long long)stopped);
        printf_notification(msg);

        free(buf);
    }
    return 0;
}
