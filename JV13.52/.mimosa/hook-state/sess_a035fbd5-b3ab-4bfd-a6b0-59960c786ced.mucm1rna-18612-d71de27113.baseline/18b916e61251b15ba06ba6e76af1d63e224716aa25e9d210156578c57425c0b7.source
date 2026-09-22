#pragma once
/*
 * self.h — PS4 SELF container structures.
 *
 * Field layout follows the SELF format as implemented by the kernel's
 * `_sceSblAuthMgrCheckSelfHeader` / `_sceSblAuthMgrGetSelfInfo` path
 * (sbl/authmgr/self_file.c) and matches AlexAltea's orbital `self_decrypter.c`,
 * which is the PS4-native reference implementation.
 *
 * The container is little-endian; the PS4 kernel and these payloads are both
 * x86-64 little-endian, so no byte swapping is required.
 */

#include "types.h"
#include "offsets_1352.h"

typedef struct self_header_t {
    uint32_t magic;        /* 0x00  SELF_MAGIC = 0x1D3D154F   */
    uint8_t  version;      /* 0x04                            */
    uint8_t  mode;         /* 0x05                            */
    uint8_t  endian;       /* 0x06  1 = little                */
    uint8_t  attr;         /* 0x07                            */
    uint32_t key_type;     /* 0x08                            */
    uint16_t header_size;  /* 0x0C                            */
    uint16_t meta_size;    /* 0x0E                            */
    uint64_t file_size;    /* 0x10                            */
    uint16_t num_entries;  /* 0x18                            */
    uint16_t flags;        /* 0x1A                            */
    uint32_t pad;          /* 0x1C                            */
} self_header_t;           /* 0x20                            */

typedef struct self_entry_t {
    uint64_t props;        /* 0x00  bitfield, see below       */
    uint64_t offset;       /* 0x08                            */
    uint64_t filesz;       /* 0x10                            */
    uint64_t memsz;        /* 0x18                            */
} self_entry_t;            /* 0x20                            */

typedef struct self_block_extent_t {
    uint32_t offset;
    uint32_t size;
} self_block_extent_t;

typedef struct self_block_info_t {
    uint32_t size;
    uint16_t index;
    self_block_extent_t extent;
    uint8_t  digest[SELF_DIGEST_SIZE];
} self_block_info_t;

/* props bitfields — same encoding the kernel uses */
#define SELF_PROPS_ORDERED(B)         B(0, 0)
#define SELF_PROPS_ENCRYPTED(B)       B(1, 1)
#define SELF_PROPS_SIGNED(B)          B(2, 2)
#define SELF_PROPS_COMPRESSED(B)      B(3, 3)
#define SELF_PROPS_WINDOW(B)          B(10, 8)
#define SELF_PROPS_BLOCKED(B)         B(11, 11)
#define SELF_PROPS_BLOCK_SIZE(B)      B(15, 12)
#define SELF_PROPS_HAS_DIGESTS(B)     B(16, 16)
#define SELF_PROPS_HAS_EXTENTS(B)     B(17, 17)
#define SELF_PROPS_SEGMENT_INDEX(B)   B(31, 20)

#define EXTRACT(v, bits) \
    (((v) >> (bits##_START)) & ((1ULL << ((bits##_END) - (bits##_START) + 1)) - 1ULL))

#define SELF_PROPS_ORDERED_START         0
#define SELF_PROPS_ORDERED_END           0
#define SELF_PROPS_ENCRYPTED_START       1
#define SELF_PROPS_ENCRYPTED_END         1
#define SELF_PROPS_SIGNED_START          2
#define SELF_PROPS_SIGNED_END            2
#define SELF_PROPS_COMPRESSED_START      3
#define SELF_PROPS_COMPRESSED_END        3
#define SELF_PROPS_WINDOW_START          8
#define SELF_PROPS_WINDOW_END            10
#define SELF_PROPS_BLOCKED_START         11
#define SELF_PROPS_BLOCKED_END           11
#define SELF_PROPS_BLOCK_SIZE_START      12
#define SELF_PROPS_BLOCK_SIZE_END        15
#define SELF_PROPS_HAS_DIGESTS_START     16
#define SELF_PROPS_HAS_DIGESTS_END       16
#define SELF_PROPS_HAS_EXTENTS_START     17
#define SELF_PROPS_HAS_EXTENTS_END       17
#define SELF_PROPS_SEGMENT_INDEX_START   20
#define SELF_PROPS_SEGMENT_INDEX_END     31

/*
 * A SELF held in memory: header + entry table + raw container bytes.
 * Mirrors the `self_t` object in orbital's self_decrypter.c, minus the
 * filesystem plumbing (we already have the bytes).
 */
typedef struct self_t {
    const uint8_t *data;       /* whole container                    */
    uint64_t       size;       /* container size                     */
    self_header_t  header;
    self_entry_t  *entries;    /* header.num_entries of them         */
    uint32_t       entries_size;

    int            ctx_id;     /* auth-manager context id, -1 = none */
    int            auth_ctx_id;
    int            verified;
} self_t;

/* Validate header + locate the entry table. Returns 0 on success. */
static inline int self_parse(self_t *s, const uint8_t *buf, uint64_t len) {
    if (len < sizeof(self_header_t))
        return -1;

    const self_header_t *h = (const self_header_t *)buf;
    if (h->magic != SELF_MAGIC || h->version != SELF_VERSION ||
        h->mode != SELF_MODE || h->endian != SELF_ENDIANNESS)
        return -2;
    if (h->file_size != len)
        return -3;
    if (h->header_size + h->meta_size > 0x4000)
        return -4;

    s->data    = buf;
    s->size    = len;
    s->header  = *h;
    s->entries = (self_entry_t *)(buf + sizeof(self_header_t));
    s->entries_size = (uint32_t)h->num_entries * (uint32_t)sizeof(self_entry_t);

    if (h->header_size < sizeof(self_header_t) + s->entries_size)
        return -5;
    if ((uint64_t)sizeof(self_header_t) + s->entries_size > len)
        return -6;

    s->ctx_id      = -1;
    s->auth_ctx_id = -1;
    s->verified    = 0;
    return 0;
}

/*
 * Resolve the digest/extent table entry that describes block `info->index`
 * of segment `target_entry_idx`. Ported from orbital self_get_block_info().
 */
static inline void self_get_block_info(const self_t *s, uint32_t target_entry_idx,
                                       self_block_info_t *info) {
    uint32_t i;

    memset(&info->digest, 0, sizeof(info->digest));
    memset(&info->extent, 0, sizeof(info->extent));

    for (i = 0; i < s->header.num_entries; ++i) {
        const self_entry_t *table_segment = &s->entries[i];
        const self_entry_t *target_segment;
        const self_block_extent_t *extents;
        const uint8_t *segment_data;
        uint32_t target_num_blocks;

        if (!EXTRACT(table_segment->props, SELF_PROPS_HAS_DIGESTS) &&
            !EXTRACT(table_segment->props, SELF_PROPS_HAS_EXTENTS))
            continue;
        if (EXTRACT(table_segment->props, SELF_PROPS_SEGMENT_INDEX) != target_entry_idx)
            continue;

        target_segment = &s->entries[target_entry_idx];
        target_num_blocks = (uint32_t)((target_segment->memsz + (info->size - 1)) / info->size);
        segment_data = &s->data[table_segment->offset];

        if (EXTRACT(table_segment->props, SELF_PROPS_HAS_DIGESTS)) {
            memcpy(&info->digest,
                   &segment_data[info->index * sizeof(info->digest)],
                   sizeof(info->digest));
        }
        if (EXTRACT(table_segment->props, SELF_PROPS_HAS_EXTENTS)) {
            if (EXTRACT(table_segment->props, SELF_PROPS_HAS_DIGESTS))
                extents = (const self_block_extent_t *)
                          (&segment_data[target_num_blocks * sizeof(info->digest)]);
            else
                extents = (const self_block_extent_t *)(&segment_data[0]);
            memcpy(&info->extent, &extents[info->index], sizeof(info->extent));
        }
        return;
    }
}
