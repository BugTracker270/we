/*
 * kmemfull v1 — dump the ENTIRE 13.52 kernel image to USB in one pass.
 *
 * WHY THIS IS A NEW PAYLOAD AND NOT kmemdump v10
 * ----------------------------------------------
 * v10 was a probe. Its default window was 128 KiB and it STOPPED at the first
 * failing read. Both are wrong for what we want now: the whole image, in one
 * run, with holes marked rather than fatal.
 *
 * RANGE — two independent sources that agree exactly
 * --------------------------------------------------
 *   1. dec/1352/80010002.self program header (we parsed it this session):
 *        p_vaddr  = 0x680000
 *        p_filesz = 0x14a65e8   ( == p_memsz )
 *      -> a flat image of 0x1b265e8 bytes.
 *   2. kmemdump/include/offsets_1352.h, derived from the live console earlier:
 *        KO_1352_TEXT_BASE     0x0            (abs 0xffffffff82200000)
 *        KO_1352_TEXT_END      0x00cfe758     (end of .text)
 *        KO_1352_DATA_START    0x01520000     (abs 0xffffffff83720000)
 *        KO_1352_DATA_FILE_END 0x01b265e8     (end of file-backed .data)
 *      v9 also PROVED both ends readable: kbase+0x1520000 returned "ORBISS",
 *      kbase+0x1b265e8 returned 0. So start=0x0, end=0x1b265e8 is the image.
 *
 * WHAT CHANGED vs v10
 * -------------------
 *   1. CONTINUE past read failures. v10 broke out. A single unmapped hole would
 *      have truncated the dump. Now each hole is recorded, zero-filled so the
 *      file stays a flat address-aligned image, and the walk carries on.
 *   2. Incremental writes + a live status file, so a softlock costs only the
 *      remainder, and the run is resumable via kmemfull.cfg start=.
 *   3. An 8-byte readability gate BEFORE any bulk work. If that fails we abort
 *      clean instead of hammering the console.
 *
 * Still no kernel calls. Only get_memory_dump().
 */

#include "ps4.h"
#include "offsets_1352.h"

#define CFG_FILE "/mnt/usb0/kmemfull.cfg"
#define OUT_FILE "/mnt/usb0/kmemfull.bin"
#define TXT_FILE "/mnt/usb0/kmemfull.txt"

#define DEF_START 0x000000000ULL
#define DEF_END   0x01b265e8ULL
#define DEF_CHUNK 0x00001000ULL
#define MAX_CHUNK 0x00040000ULL

static uint64_t g_kbase = 0;

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

static void cfg_line(char *line, uint64_t *start, uint64_t *end, uint64_t *chunk)
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
    }
}

static void parse_cfg(uint64_t *start, uint64_t *end, uint64_t *chunk)
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
        cfg_line(p, start, end, chunk);
        if (!had)
            break;
        p = e + 1;
    }
}

int _main(struct thread *td)
{
    char msg[200];
    uint64_t start = DEF_START, end = DEF_END, chunk = DEF_CHUNK;
    uint64_t probe = 0, total, off, done = 0;
    uint32_t reads = 0, holes = 0;
    uint64_t first_hole = 0, last_hole = 0;
    uint8_t *buf;
    int bf, tf, r;

    initKernel();
    initLibc();
    initPthread();
    initNetwork();
    initSysUtil();

    printf_notification("KMEMFULL v1: start");

    g_kbase = get_kernel_base();
    if (!g_kbase) {
        printf_notification("KMEMFULL ABORT: no kernel base");
        return 0;
    }
    jailbreak();
    mmap_patch();

    snprintf(msg, sizeof(msg), "KMEMFULL kbase=%llx",
             (unsigned long long)g_kbase);
    printf_notification(msg);

    parse_cfg(&start, &end, &chunk);
    if (chunk < 8)
        chunk = 8;
    if (chunk > MAX_CHUNK)
        chunk = MAX_CHUNK;
    if (end <= start)
        end = start + chunk;

    total = end - start;

    /* --- readability gate: 8 bytes. If this fails, stop cleanly. --- */
    r = get_memory_dump(g_kbase + start, (uint64_t *)&probe, 8);
    if (r != 0) {
        snprintf(msg, sizeof(msg), "KMEMFULL ABORT: gate r=%d", r);
        printf_notification(msg);
        return 0;
    }
    {
        uint64_t rel = 0;
        if (start == DEF_START && probe) {
            /* sanity: first 8 bytes of the image, purely informational */
            rel = probe;
        }
        snprintf(msg, sizeof(msg), "KMEMFULL gate ok first8=%llx",
                 (unsigned long long)rel);
        printf_notification(msg);
    }

    snprintf(msg, sizeof(msg), "KMEMFULL range %llx-%llx chunk=%llx total=%llu",
             (unsigned long long)start, (unsigned long long)end,
             (unsigned long long)chunk, (unsigned long long)total);
    printf_notification(msg);

    tf = open(TXT_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (tf >= 0) {
        char h[200];
        int L = snprintf(h, sizeof(h),
                         "kbase=0x%llx\nstart=0x%llx\nend=0x%llx\nchunk=0x%llx\n"
                         "total=%llu\n",
                         (unsigned long long)g_kbase,
                         (unsigned long long)start, (unsigned long long)end,
                         (unsigned long long)chunk, (unsigned long long)total);
        write_all(tf, (const uint8_t *)h, (uint64_t)L);
    }

    buf = (uint8_t *)malloc((size_t)chunk);
    if (!buf) {
        printf_notification("KMEMFULL ABORT: no buffer");
        if (tf >= 0)
            close(tf);
        return 0;
    }

    bf = open(OUT_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (bf < 0) {
        printf_notification("KMEMFULL ABORT: cannot open output");
        free(buf);
        if (tf >= 0)
            close(tf);
        return 0;
    }

    for (off = start; off < end; off += chunk) {
        uint64_t n = end - off;
        if (n > chunk)
            n = chunk;

        r = get_memory_dump(g_kbase + off, (uint64_t *)buf, (size_t)n);
        if (r != 0) {
            /* HOLE: keep the file flat, record it, and carry on. v10 stopped. */
            memset(buf, 0, (size_t)n);
            if (holes == 0)
                first_hole = off;
            last_hole = off;
            holes++;
        } else {
            reads++;
        }

        if (write_all(bf, buf, n) < 0) {
            snprintf(msg, sizeof(msg), "KMEMFULL write fail @%llx",
                     (unsigned long long)off);
            printf_notification(msg);
            break;
        }
        done += n;

        if (((reads + holes) & 255) == 0 && tf >= 0) {
            char s[200];
            int L = snprintf(s, sizeof(s),
                             "off=0x%llx done=%llu/%llu ok=%u holes=%u\n",
                             (unsigned long long)(off + n),
                             (unsigned long long)done, (unsigned long long)total,
                             reads, holes);
            status(tf, s, L);
        }
        if ((reads + holes) < 4 || ((reads + holes) & 1023) == 0) {
            snprintf(msg, sizeof(msg), "KMEMFULL %llx %lluB ok=%u h=%u",
                     (unsigned long long)(off + g_kbase),
                     (unsigned long long)done, reads, holes);
            printf_notification(msg);
        }
    }

    close(bf);

    if (tf >= 0) {
        char s[300];
        int L = snprintf(s, sizeof(s),
                         "DONE\ndone=%llu\ntotal=%llu\nreads_ok=%u\nholes=%u\n"
                         "first_hole=0x%llx\nlast_hole=0x%llx\n",
                         (unsigned long long)done, (unsigned long long)total,
                         reads, holes, (unsigned long long)first_hole,
                         (unsigned long long)last_hole);
        status(tf, s, L);
        close(tf);
    }
    free(buf);

    snprintf(msg, sizeof(msg), "KMEMFULL done %lluB ok=%u holes=%u",
             (unsigned long long)done, reads, holes);
    printf_notification(msg);
    return 0;
}
