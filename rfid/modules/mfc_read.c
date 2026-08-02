/* rfid feature module: MIFARE Classic READ (`read mfc`).
 *
 * A pure dictionary read: try candidate keys against every sector (Key A then B, with key reuse) and dump the
 * blocks under whichever key can read each. Reads the card-specific /nfc/mfc.dict (keys `collect mfc sniff`
 * recovered) first, then the general dictionary at /mfc_cand - both plain uppercase-ASCII-hex (one key/line),
 * streamed via pread and parsed line-by-line so no whole dict lands in the module heap. Nonce collection lives
 * in `collect`, not here - this module only authenticates and reads. */
#include "mfc_common.h"

#define MFC_DICT_PATH "/nfc/mfc.dict"     /* card-specific keys from collect+mfkey64 (tried first) */
#define MFC_CAND_PATH "/nfc/mfc_dict.dic" /* the general dictionary, flashed as a resource by `make flash` */
#define MFC_REC       13                  /* fixed dict record: 12 uppercase-hex chars + '\n' (no comments) */

/* A flat 12-hex-char-per-line-plus-\n dictionary: read one key at a time by offset (i*13), so the module
 * only ever holds a single key. Each key is tried in every still-empty Key A / Key B slot (key reuse). A
 * sector whose auth returns "no nonce" (mfc_auth == -2) doesn't exist on this card - it's marked absent so
 * later keys skip it (a plain 1K wastes no time grinding the whole dict against EV1 sectors 16/17). Stops as
 * soon as every sector is solved or absent, so common cards finish in a key or two. `absent` persists across
 * the two dict files. */
static void dict_check(const fantasi_rfid_t *r, const fantasi_api_t *api, uint32_t uid,
                       const char *path, uint64_t *akey, uint64_t *bkey, int8_t *absent, int *solved)
{
    if (api->file_size(path) < 12) return;
    for (int i = 0; ; i++) {
        int any = 0;                                       /* still a slot worth trying? */
        for (int s = 0; s < MFC_SECTORS; s++)
            if (!absent[s] && (akey[s] == KEY_NONE || bkey[s] == KEY_NONE)) { any = 1; break; }
        if (!any) return;

        uint8_t rec[12];
        if (api->pread(path, (uint32_t)i * MFC_REC, rec, 12) < 12) break;   /* 12 hex; the \n is skipped */
        uint64_t key = 0; int ok = 1;
        for (int j = 0; j < 12; j++) {
            uint8_t c = rec[j], v;
            if (c >= '0' && c <= '9') v = c - '0';
            else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
            else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
            else { ok = 0; break; }
            key = key << 4 | v;
        }
        if (!ok) continue;
        for (int s = 0; s < MFC_SECTORS; s++) {
            if (absent[s]) continue;
            for (int kt = 0; kt < 2; kt++) {
                uint64_t *slot = kt ? &bkey[s] : &akey[s];
                if (*slot != KEY_NONE) continue;
                uint8_t u2[4], s2; c1_t cs;
                if (mfc_activate(r, api, u2, &s2, 0) != 0) continue;
                int rc = mfc_auth(r, uid, (uint8_t)(s * 4), kt, key, &cs);
                if (rc == -2) { absent[s] = 1; break; }     /* sector doesn't exist - skip it hereafter */
                if (rc == 0) { *slot = key; (*solved)++; }
            }
        }
    }
}

int app_main(const fantasi_api_t *api)
{
    const fantasi_rfid_t *r = fantasi_rfid();
    if (!r || !r->hf_transceive_par || !(r->caps() & FANTASI_RFID_CAP_HF_READ)) {
        api->print("mfc: not supported on this device\r\n"); return 0;
    }
    if (!api->pread) { api->print("mfc: firmware has no pread\r\n"); return 0; }
    if (r->set_mode(FANTASI_RFID_HF_READER) != 0) { api->print("mfc: HF frontend unavailable\r\n"); return 0; }

    uint8_t uid[4], sak = 0, atqa[2] = {0};
    if (mfc_activate(r, api, uid, &sak, atqa) != 0) {
        r->set_mode(FANTASI_RFID_OFF);
        api->print("mfc: no MIFARE Classic card (or 7-byte UID)\r\n"); return 0;
    }
    uint32_t uid32 = be32(uid);
    char uh[9]; put_hex(uh, uid, 4);
    api->printf("mfc: uid=%s sak=%02X atqa=%02X%02X\r\n", uh, sak, atqa[1], atqa[0]);

    /* Profile the PRNG: a weak/static card's nt is always a valid weak-LFSR value, a hardened card's is not.
     * Host records this in the saved JSON ("prng") so `emulate` knows the class. (mfc_get_nt self-activates.) */
    int nonweak = 0, nsamp = 0; uint32_t nt;
    for (int i = 0; i < 5; i++) {
        if (mfc_get_nt(r, api, &nt) == 0) { nsamp++; if (!is_weak_prng_nonce(nt)) nonweak++; }
        r->field(0); api->delay(2); r->field(1); api->delay(2);   /* mfc_get_nt's AUTH has no nr/ar, leaving the
                                                                   * card mid-crypto; a field cycle re-idles it so
                                                                   * the next sample and dict_check can re-select */
    }
    api->printf("mfc: prng=%s\r\n", (nsamp && nonweak >= 3) ? "hard" : "weak");

    uint64_t akey[MFC_SECTORS], bkey[MFC_SECTORS]; int8_t absent[MFC_SECTORS];
    for (int i = 0; i < MFC_SECTORS; i++) { akey[i] = bkey[i] = KEY_NONE; absent[i] = 0; }
    int solved = 0;
    dict_check(r, api, uid32, MFC_DICT_PATH, akey, bkey, absent, &solved);   /* card-specific keys (collect+mfkey64) first */
    dict_check(r, api, uid32, MFC_CAND_PATH, akey, bkey, absent, &solved);   /* then the general dictionary */

    /* Dump each sector: auth once per keytype (Key A then B) and read the 4 blocks that key can, so access
     * bits that grant read to only one key still yield a full dump. */
    int nsec = 0;
    for (int s = 0; s < MFC_SECTORS; s++) {
        int base = s * 4;
        uint64_t k2[2] = { akey[s], bkey[s] };
        if (k2[0] != KEY_NONE || k2[1] != KEY_NONE) nsec++;
        for (int kt = 0; kt < 2; kt++) if (k2[kt] != KEY_NONE) {
            uint8_t kb[6]; char kh[13];
            for (int i = 0; i < 6; i++) kb[i] = (uint8_t)(k2[kt] >> (40 - i * 8));
            put_hex(kh, kb, 6);
            api->printf("mfc: sec %02d key%c=%s\r\n", s, kt ? 'B' : 'A', kh);
        }
        uint8_t data[4][16]; int done[4], ndone = 0; for (int i = 0; i < 4; i++) done[i] = 0;
        for (int kt = 0; kt < 2 && ndone < 4; kt++) {
            if (k2[kt] == KEY_NONE) continue;
            c1_t cs; uint8_t u2[4], s2;
            if (mfc_activate(r, api, u2, &s2, 0) != 0 || mfc_auth(r, uid32, (uint8_t)base, kt, k2[kt], &cs) != 0) continue;
            for (int b = 0; b < 4; b++) if (!done[b] && mfc_read(r, &cs, (uint8_t)(base + b), data[b]) == 0) { done[b] = 1; ndone++; }
        }
        for (int b = 0; b < 4; b++) {
            char dh[33];
            if (done[b]) { put_hex(dh, data[b], 16); api->printf("mfc: blk %02d = %s\r\n", base + b, dh); }
            else api->printf("mfc: blk %02d = locked\r\n", base + b);
        }
    }

    r->set_mode(FANTASI_RFID_OFF);
    api->printf("mfc: done %d sectors\r\n", nsec);
    return 1;
}
