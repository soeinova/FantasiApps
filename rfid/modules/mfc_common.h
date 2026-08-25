/* Shared MIFARE Classic on-card primitives for the rfid mfc modules.
 *
 * The mfc read is split into two hot-loaded modules - mfc_collect (samples the PRNG, bootstraps a key,
 * harvests nested nonces) and mfc_read (authenticates + reads blocks with host-solved keys) - so each ELF
 * stays small enough to load into the tight PM3 /ramfs heap without an OOM. Everything time-sensitive (the
 * on-card Crypto1 auth/nested-auth/read timing) lives here; everything offline (PRNG classification, the
 * Crypto1 rollback/decrypt, the dictionary match) lives on the host, which also holds the dictionary - so
 * the device never carries the 12 KB dict nor the matcher. Both modules #include this header and, with
 * --gc-sections, keep only the primitives they actually call.
 *
 * Cipher + auth/read ported from proxmark3 common/crapto1 + armsrc/mifareutil.c. */
#ifndef FANTASI_RFID_MFC_COMMON_H
#define FANTASI_RFID_MFC_COMMON_H

#include "app_api.h"
#include "app_rfid.h"

#define MFC_SECTORS 16                    /* MIFARE Classic 1K: 16 sectors x 4 blocks, two keys per sector */
#define KEY_NONE 0xFFFFFFFFFFFFFFFFULL     /* sentinel: a Key A/B slot not yet recovered */
#define MFC_COLLECT 8                      /* nested nonces harvested per unsolved slot (enough for the hard
                                           * parity filter; the host uses 1 on a weak PRNG, all 8 on a hard one) */

/* ---- Crypto1 cipher (ported from proxmark3 common/crapto1/crypto1.c) ---- */
#define LF_POLY_ODD  0x29CE5Cu
#define LF_POLY_EVEN 0x870804u
#define BIT(x, n)    ((uint32_t)((x) >> (n) & 1))
#define BEBIT(x, n)  BIT(x, (n) ^ 24)

/* Parity by bit-folding (not __builtin_parity - that compiles to a libgcc __paritysi2 the module loader
 * can't resolve). oddparity8 = the bit making {byte,parity} odd; evenparity32 = XOR of all bits. */
static inline uint8_t oddparity8(uint8_t x)
{ x ^= x >> 4; x ^= x >> 2; x ^= x >> 1; return (uint8_t)(~x & 1); }
static inline uint32_t evenparity32(uint32_t x)
{ x ^= x >> 16; x ^= x >> 8; x ^= x >> 4; x ^= x >> 2; x ^= x >> 1; return x & 1; }

/* Force-inline the Crypto1 hot path only in the emu module (MFC_FAST_FILTER): it removes the -mlong-calls
 * overhead for a lower FDT, but the extra code bloats a module. read/collect keep plain static funcs so
 * their (bigger) ELFs still fit the ramfs load budget. */
#ifdef MFC_FAST_FILTER
#define MFC_HOT static inline __attribute__((always_inline))
#else
#define MFC_HOT static
#endif

#ifdef MFC_FAST_FILTER
/* Byte-indexed table filter (aczid/crypto1_bs + noproto mfkey): folds the low two bytes of the odd
 * LFSR into the 5-bit filter index with 2 loads instead of 5 nibble-shifts. The 512 B of tables are generated
 * at runtime into a caller-provided heap buffer (mfc_filter_init) rather than stored in .rodata - the emu
 * module's ELF load budget is too tight for the const tables, but heap the module allocates after its ELF is
 * freed has room. A module that defines MFC_FAST_FILTER must call mfc_filter_init before any crypto. */
static const uint8_t *mfc_lu1, *mfc_lu2;
static void mfc_filter_init(uint8_t *t512)
{
    uint8_t *l1 = t512, *l2 = t512 + 256;
    for (int b = 0; b < 256; b++) {
        l1[b] = (uint8_t)((0xf22c0u >> (b & 0xf) & 16) | (0x6c9c0u >> (b >> 4 & 0xf) & 8));   /* index bits 4,3 */
        l2[b] = (uint8_t)((0x3c8b0u >> (b & 0xf) &  4) | (0x1e458u >> (b >> 4 & 0xf) & 2));   /* index bits 2,1 */
    }
    mfc_lu1 = l1; mfc_lu2 = l2;
}
MFC_HOT int filter(uint32_t x)
{
    uint32_t f = mfc_lu1[x & 0xff] | mfc_lu2[x >> 8 & 0xff];
    f |= 0x0d938u >> (x >> 16 & 0xf) & 1;                                                     /* index bit 0 */
    return (int)BIT(0xEC57E80Au, f);
}
#else
MFC_HOT int filter(uint32_t x)
{
    uint32_t f;
    f  = 0xf22c0u >> (x       & 0xf) & 16;
    f |= 0x6c9c0u >> (x >>  4 & 0xf) &  8;
    f |= 0x3c8b0u >> (x >>  8 & 0xf) &  4;
    f |= 0x1e458u >> (x >> 12 & 0xf) &  2;
    f |= 0x0d938u >> (x >> 16 & 0xf) &  1;
    return (int)BIT(0xEC57E80Au, f);
}
#endif

typedef struct { uint32_t odd, even; } c1_t;

static void c1_init(c1_t *s, uint64_t key)
{
    s->odd = s->even = 0;
    for (int i = 47; i > 0; i -= 2) {
        s->odd  = s->odd  << 1 | BIT(key, (i - 1) ^ 7);
        s->even = s->even << 1 | BIT(key, i ^ 7);
    }
}

MFC_HOT uint8_t c1_bit(c1_t *s, uint8_t in, int enc)
{
    uint32_t feedin, t;
    uint8_t ret = (uint8_t)filter(s->odd);
    feedin  = ret & (!!enc);
    feedin ^= !!in;
    feedin ^= LF_POLY_ODD  & s->odd;
    feedin ^= LF_POLY_EVEN & s->even;
    s->even = s->even << 1 | evenparity32(feedin);
    t = s->odd; s->odd = s->even; s->even = t;
    return ret;
}

MFC_HOT uint8_t c1_byte(c1_t *s, uint8_t in, int enc)
{
    uint8_t r = 0;
    for (int i = 0; i < 8; i++) r |= c1_bit(s, (uint8_t)BIT(in, i), enc) << i;
    return r;
}

static inline uint32_t c1_word(c1_t *s, uint32_t in, int enc)
{
    uint32_t r = 0;
    for (int i = 0; i < 32; i++) r |= (uint32_t)c1_bit(s, (uint8_t)BEBIT(in, i), enc) << (24 ^ i);
    return r;
}

#define SWAPENDIAN(x) (x = (x >> 8 & 0xff00ff) | (x & 0xff00ff) << 8, x = x >> 16 | x << 16)
static uint32_t prng_successor(uint32_t x, uint32_t n)
{
    SWAPENDIAN(x);
    while (n--) x = x >> 1 | (x >> 16 ^ x >> 18 ^ x >> 19 ^ x >> 21) << 31;
    return SWAPENDIAN(x);
}

/* Lightweight PRNG classifier (== pm3 validate_prng_nonce): low 16 bits are the 16-shift successor of the
 * high 16 on a weak card. Just a classifier (picks the log format) - the heavy offline matcher stays host-side. */
static inline int is_weak_prng_nonce(uint32_t nonce)
{
    if (nonce == 0) return 0;
    uint16_t x = (uint16_t)(nonce >> 16);
    x = (uint16_t)((x & 0xff) << 8 | x >> 8);
    for (int i = 0; i < 16; i++)
        x = (uint16_t)(x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15);
    x = (uint16_t)((x & 0xff) << 8 | x >> 8);
    return x == (nonce & 0xFFFF);
}

/* ---- helpers ---- */
static uint32_t be32(const uint8_t *b) { return (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3]; }

/* Uppercase-hex-encode n bytes into out (needs 2n+1). One small loop replaces many-arg %02X printfs. */
static __attribute__((unused)) void put_hex(char *out, const uint8_t *b, int n)
{
    static const char H[] = "0123456789ABCDEF";
    for (int i = 0; i < n; i++) { out[i * 2] = H[b[i] >> 4]; out[i * 2 + 1] = H[b[i] & 15]; }
    out[n * 2] = 0;
}

static __attribute__((unused)) int mfc_parse_key12(const uint8_t *s, uint64_t *key)
{
    uint64_t v = 0;
    for (int i = 0; i < 12; i++) {
        uint8_t c = s[i], n;
        if (c >= '0' && c <= '9') n = c - '0';
        else if (c >= 'A' && c <= 'F') n = c - 'A' + 10;
        else if (c >= 'a' && c <= 'f') n = c - 'a' + 10;
        else return 0;
        v = v << 4 | n;
    }
    *key = v;
    return 1;
}

/* ISO14443-A CRC (poly 0x8408, preset 0x6363), written LSB then MSB after `d[0..n]`. */
static void crc_a(const uint8_t *d, int n, uint8_t *out)
{
    uint16_t crc = 0x6363;
    for (int i = 0; i < n; i++) {
        uint8_t b = (uint8_t)(d[i] ^ (crc & 0xFF));
        b ^= (uint8_t)(b << 4);
        crc = (uint16_t)((crc >> 8) ^ ((uint16_t)b << 8) ^ ((uint16_t)b << 3) ^ ((uint16_t)b >> 4));
    }
    out[0] = (uint8_t)crc; out[1] = (uint8_t)(crc >> 8);
}

/* ---- ISO14443-A activation ---- */
/* Use the firmware's common selector rather than carrying a subtly different
 * anticollision implementation in every MFC module.  A failed authentication
 * normally returns a Classic tag to IDLE, so the selector's REQA works on the
 * fast path.  If the tag was instead left HALTed or mid-crypto, one field cycle
 * returns it to IDLE before the bounded retry. */
static int mfc_activate(const fantasi_rfid_t *r, const fantasi_api_t *api, uint8_t uid[4], uint8_t *sak, uint8_t atqa[2])
{
    uint8_t full_uid[10], a[2];
    int uid_len, cascade;
    for (int attempt = 0; attempt < 2; attempt++) {
        uid_len = 0;
        if (r->iso14443a_select(full_uid, &uid_len, sak, a, &cascade) == 0) {
            if (uid_len != 4) return -1;
            for (int i = 0; i < 4; i++) uid[i] = full_uid[i];
            if (atqa) { atqa[0] = a[0]; atqa[1] = a[1]; }
            return 0;
        }
        r->field(0); api->delay(2);
        r->field(1); api->delay(2);
    }
    return -1;
}

/* ---- Crypto1 auth (AUTH_FIRST). Assumes the card is already selected. Leaves *cs post-auth. Returns 0 on
 * success, -1 on a wrong key (the tag answered with a nonce but the handshake failed), or -2 when the tag
 * sent no nonce. Every sector addressed by the 1K reader exists, so -2 is RF/card loss, not an "absent"
 * sector inferred from one failed exchange. ---- */
static int mfc_auth(const fantasi_rfid_t *r, uint32_t uid, uint8_t block, int keytype, uint64_t key, c1_t *cs)
{
    uint8_t cmd[4] = { (uint8_t)(0x60 + (keytype & 1)), block, 0, 0 };
    crc_a(cmd, 2, cmd + 2);
    uint8_t rx[16];
    if (r->hf_transceive(cmd, 32, 0, rx, sizeof rx, 0) < 32) return -2;   /* no nt -> sector/block absent */
    uint32_t nt = be32(rx);

    c1_init(cs, key);
    c1_word(cs, nt ^ uid, 0);                              /* AUTH_FIRST: load uid^nt in clear */

    uint8_t nr[4] = { 0x52, 0x9a, 0xf1, 0x0c };
    uint8_t nrar[8], par[8];
    for (int i = 0; i < 4; i++) {
        nrar[i] = (uint8_t)(c1_byte(cs, nr[i], 0) ^ nr[i]);
        par[i]  = (uint8_t)((filter(cs->odd) ^ oddparity8(nr[i])) & 1);
    }
    nt = prng_successor(nt, 32);
    for (int i = 4; i < 8; i++) {
        nt = prng_successor(nt, 8);
        nrar[i] = (uint8_t)(c1_byte(cs, 0, 0) ^ (nt & 0xff));
        par[i]  = (uint8_t)((filter(cs->odd) ^ oddparity8((uint8_t)(nt & 0xff))) & 1);
    }
    if (r->hf_transceive_par(nrar, 8, par, rx, NULL, sizeof rx, 0) < 32) return -1;   /* -> {aT} (4 bytes) */

    uint32_t ntpp = prng_successor(nt, 32) ^ c1_word(cs, 0, 0);
    return (ntpp == be32(rx)) ? 0 : -1;
}

/* ---- encrypted read (0x30) after a successful auth. Decrypts into out[16]. 0 / -1. ---- */
static inline int mfc_read(const fantasi_rfid_t *r, c1_t *cs, uint8_t block, uint8_t out[16])
{
    uint8_t cmd[4] = { 0x30, block, 0, 0 }, ecmd[4], par[4];
    crc_a(cmd, 2, cmd + 2);
    for (int i = 0; i < 4; i++) {
        ecmd[i] = (uint8_t)(c1_byte(cs, 0, 0) ^ cmd[i]);
        par[i]  = (uint8_t)((filter(cs->odd) ^ oddparity8(cmd[i])) & 1);
    }
    uint8_t rx[18];
    int nb = r->hf_transceive_par(ecmd, 4, par, rx, NULL, sizeof rx, 0);
    if (nb < 18 * 8) return -1;                            /* 16 data + 2 CRC, encrypted */
    for (int i = 0; i < 18; i++) rx[i] = (uint8_t)(c1_byte(cs, 0, 0) ^ rx[i]);   /* decrypt */
    uint8_t crc[2]; crc_a(rx, 16, crc);
    if (crc[0] != rx[16] || crc[1] != rx[17]) return -1;   /* CRC over the decrypted data */
    for (int i = 0; i < 16; i++) out[i] = rx[i];
    return 0;
}

/* Capture one plaintext tag nonce (a first-auth nt, sent in the clear) from block 0 to sample the PRNG. */
static inline int mfc_get_nt(const fantasi_rfid_t *r, const fantasi_api_t *api, uint32_t *nt)
{
    uint8_t u2[4], s2, a2[2];
    if (mfc_activate(r, api, u2, &s2, a2) != 0) return -1;
    uint8_t cmd[4] = { 0x60, 0, 0, 0 };
    crc_a(cmd, 2, cmd + 2);
    uint8_t rx[8];
    if (r->hf_transceive(cmd, 32, 0, rx, sizeof rx, 0) < 32) return -1;
    *nt = be32(rx);
    return 0;
}

/* Nested-nonce collection: full-auth the known sector, then issue an encrypted nested auth toward the target
 * block (early return - no nr/aR), capturing the target's encrypted nonce *nt_enc + its 4 raw air parity bits
 * packed MSB-first, each XOR 1 (Flipper representation). ntenc stays raw: the dictionary is matched against it
 * offline on the host. Mirrors mifare_classic_authex_cmd's AUTH_Nested path up to ntenc. 0 / -1. */
static inline int mfc_collect_nested(const fantasi_rfid_t *r, const fantasi_api_t *api, uint32_t uid,
                              uint8_t known_block, int known_type, uint64_t known_key,
                              uint8_t target_block, int target_type, uint32_t *nt_enc, uint8_t *parpk)
{
    uint8_t u2[4], s2; c1_t cs;
    if (mfc_activate(r, api, u2, &s2, 0) != 0) return -1;       /* select (mfc_auth assumes selected) */
    if (mfc_auth(r, uid, known_block, known_type, known_key, &cs) != 0) return -1;

    uint8_t cmd[4] = { (uint8_t)(0x60 + (target_type & 1)), target_block, 0, 0 };
    crc_a(cmd, 2, cmd + 2);
    uint8_t ecmd[4], par[4];
    for (int i = 0; i < 4; i++) {
        ecmd[i] = (uint8_t)(c1_byte(&cs, 0, 0) ^ cmd[i]);       /* keystream-encrypt the cmd (input 0) */
        par[i]  = (uint8_t)((filter(cs.odd) ^ oddparity8(cmd[i])) & 1);
    }
    uint8_t rx[8], rxpar[8] = {0};
    if (r->hf_transceive_par(ecmd, 4, par, rx, rxpar, sizeof rx, 0) < 32) return -1;   /* -> nt_enc (4 bytes) */
    *nt_enc = be32(rx);
    uint8_t pk = 0;
    for (int i = 0; i < 4; i++) pk = (uint8_t)((pk << 1) | ((rxpar[i] & 1) ^ 1));
    *parpk = pk;
    return 0;
}

/* Common default keys tried on-card to bootstrap one known key (the nested attack needs a foothold, and the
 * dictionary is host-side now). Just the handful that open real cards' sector 0; the host's full dictionary
 * (via nested nonces) covers everything else. */
static const uint64_t MFC_BOOT_KEYS[] = {
    0xFFFFFFFFFFFFULL, 0x000000000000ULL, 0xA0A1A2A3A4A5ULL, 0xD3F7D3F7D3F7ULL,
    0xA0B0C0D0E0F0ULL, 0x1A2B3C4D5E6FULL, 0xB0B1B2B3B4B5ULL, 0x4D3A99C351DDULL,
    0x1A982C7E459AULL, 0xAABBCCDDEEFFULL, 0x714C5C886E97ULL, 0x587EE5F9350FULL,
};
#define MFC_NBOOT ((int)(sizeof MFC_BOOT_KEYS / sizeof MFC_BOOT_KEYS[0]))

#endif /* FANTASI_RFID_MFC_COMMON_H */
