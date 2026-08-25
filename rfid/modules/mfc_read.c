/* rfid feature module: MIFARE Classic READ (`read mfc`).
 *
 * A pure dictionary read: find one usable key per sector and read with it first. If the trailer configuration
 * exposes Key B as data, recover that value directly; otherwise dictionary-check the missing A/B key before
 * finishing the sector. This still reports both keys, without grinding through the whole dictionary trying to
 * authenticate with a Key-B field that the card has configured as readable data. Both dictionaries are
 * streamed one record at a time, so neither one nor a whole-card buffer lands in the module heap. */
#include "mfc_common.h"

#define MFC_DICT_PATH "/nfc/mfc.dict"     /* card-specific keys from collect+mfkey64 (tried first) */
#define MFC_CAND_PATH "/nfc/mfc_dict.dic" /* the general dictionary, flashed as a resource by `make flash` */
#define MFC_KEY_PATH  "/ramfs/.mfckey"    /* optional host-supplied key, treated as a one-record dictionary */
#define MFC_REC       13                  /* fixed dict record: 12 uppercase-hex chars + '\n' (no comments) */

/* First pass: stop once every present sector has either Key A or Key B. The previous implementation required
 * both before reading; on common transport trailers Key B is readable data rather than an authentication key,
 * so it exhausted the dictionary against every B slot even though Key A could already dump the tag.
 * Wanted-slot masks make the same streaming loop usable for the initial sweep and for a single alternate
 * key later, without another parser/auth implementation or task-count-sized scratch storage. */
static inline __attribute__((always_inline)) int try_auth(
                    const fantasi_rfid_t *r, const fantasi_api_t *api, uint32_t uid,
                    int sector, int keytype, uint64_t key, c1_t *cs)
{
    for (int retry = 0; retry < 3; retry++) {
        uint8_t u2[4], s2;
        if (mfc_activate(r, api, u2, &s2, 0) == 0) {
            int rc = mfc_auth(r, uid, (uint8_t)(sector * 4), keytype, key, cs);
            if (rc != -2) return rc;
        }
    }
    return -2;
}

static int dict_check(const fantasi_rfid_t *r, const fantasi_api_t *api, uint32_t uid,
                      const char *path, uint64_t *akey, uint64_t *bkey,
                      int *solved, uint32_t *want_a, uint32_t *want_b)
{
    if (api->file_size(path) < 12) return 0;
    for (int i = 0; (*want_a | *want_b) != 0; i++) {
        uint8_t rec[12]; uint64_t key;
        if (api->pread(path, (uint32_t)i * MFC_REC, rec, 12) < 12) break;
        if (!mfc_parse_key12(rec, &key)) continue;
        int before = *solved;
        for (int s = 0; s < MFC_SECTORS; s++) {
            uint32_t bit = 1u << s;
            for (int kt = 0; kt < 2; kt++) {
                uint32_t *want = kt ? want_b : want_a;
                if (!(*want & bit)) continue;
                uint64_t *slot = kt ? &bkey[s] : &akey[s];
                c1_t cs;
                /* A key already recovered in another slot is especially likely
                 * to be reused here. Give that candidate bounded retries while
                 * unknown dictionary candidates retain the fast path. */
                int known = 0, rc = -1;
                for (int k = 0; k < MFC_SECTORS; k++)
                    if (akey[k] == key || bkey[k] == key) { known = 1; break; }
                for (int attempt = 0; attempt < (known ? 3 : 1); attempt++) {
                    rc = try_auth(r, api, uid, s, kt, key, &cs);
                    if (rc == 0 || rc == -2) break;
                }
                if (rc == -2) return -1;
                if (rc == 0) {
                    *slot = key; (*solved)++;
                    *want_a &= ~bit; *want_b &= ~bit;
                    break;
                }
            }
        }
        if (*solved != before)
            api->printf("reading: found %d key%s\r\n", *solved, *solved == 1 ? "" : "s");
    }
    return 0;
}

static void print_key(const fantasi_api_t *api, int sector, int keytype, uint64_t key)
{
    uint8_t kb[6]; char kh[13];
    for (int i = 0; i < 6; i++) kb[i] = (uint8_t)(key >> (40 - i * 8));
    put_hex(kh, kb, 6);
    api->printf("mfc: sec %02d key%c=%s\r\n", sector, keytype ? 'B' : 'A', kh);
}

static void read_sector(const fantasi_rfid_t *r, const fantasi_api_t *api, uint32_t uid,
                        int sector, int keytype, uint64_t key, uint8_t data[4][16], int done[4], int *ndone)
{
    int base = sector * 4;
    c1_t cs;
    if (try_auth(r, api, uid, sector, keytype, key, &cs) != 0) return;
    for (int b = 0; b < 4; b++) if (!done[b]) {
        int rc = mfc_read(r, &cs, (uint8_t)(base + b), data[b]);
        /* Once a READ reply is missed, the host and card cipher states may no
         * longer agree. Re-authenticate before retrying that block; on a true
         * access denial, leave it for the other key instead of ploughing ahead
         * with a desynchronised cipher and losing otherwise-readable blocks. */
        for (int retry = 0; rc != 0 && retry < 2; retry++) {
            if (try_auth(r, api, uid, sector, keytype, key, &cs) != 0) break;
            rc = mfc_read(r, &cs, (uint8_t)(base + b), data[b]);
        }
        if (rc == 0) {
            done[b] = 1;
            (*ndone)++;
        } else break;
    }
}

int app_main(const fantasi_api_t *api)
{
    const fantasi_rfid_t *r = fantasi_rfid();
    if (!r || !r->hf_transceive_par || !(r->caps() & FANTASI_RFID_CAP_HF_READ)) {
        api->print("mfc: not supported on this device\r\n"); return 0;
    }
    if (!api->pread) { api->print("mfc: firmware has no pread\r\n"); return 0; }
    api->print("reading: detecting MIFARE Classic card\r\n");
    if (r->set_mode(FANTASI_RFID_HF_READER) != 0) { api->print("mfc: HF frontend unavailable\r\n"); return 0; }
    /* `set_mode` configures the frontend, but some targets do not energise the
     * field until requested. Give the card the same 10 ms power-up interval as
     * the generic ISO14443-A scanner before the first WUPA. */
    r->field(1);
    api->delay(10);

    uint8_t uid[4], sak = 0, atqa[2] = {0};
    if (mfc_activate(r, api, uid, &sak, atqa) != 0) {
        r->set_mode(FANTASI_RFID_OFF);
        api->print("mfc: no MIFARE Classic card (or 7-byte UID)\r\n"); return 0;
    }
    uint32_t uid32 = be32(uid);
    char uh[9]; put_hex(uh, uid, 4);
    api->printf("mfc: uid=%s sak=%02X atqa=%02X%02X\r\n", uh, sak, atqa[1], atqa[0]);
    api->print("reading: profiling card\r\n");

    /* Profile the PRNG: a weak/static card's nt is always a valid weak-LFSR value, a hardened card's is not.
     * Host records this in the saved JSON ("prng") so `emulate` knows the class. (mfc_get_nt self-activates.) */
    int nonweak = 0, nsamp = 0; uint32_t nt;
    for (int i = 0; i < 5; i++) {
        if (mfc_get_nt(r, api, &nt) == 0) { nsamp++; if (!is_weak_prng_nonce(nt)) nonweak++; }
        r->field(0); api->delay(2); r->field(1); api->delay(2);   /* mfc_get_nt's AUTH has no nr/ar, leaving the
                                                                   * card mid-crypto; a field cycle re-idles it so
                                                                   * the next sample and dictionary pass can re-select */
    }
    /* Five independent activation+AUTH-nonce exchanges are already part of
     * profiling. Require all five instead of accepting a single noisy select
     * and later presenting an empty dump as success. This is a stability
     * requirement, not a vote: any failed sample fails this read. */
    if (nsamp != 5) goto card_lost;
    api->printf("mfc: prng=%s\r\n", (nsamp && nonweak >= 3) ? "hard" : "weak");

    uint64_t akey[MFC_SECTORS], bkey[MFC_SECTORS];
    for (int i = 0; i < MFC_SECTORS; i++) akey[i] = bkey[i] = KEY_NONE;
    int solved = 0;
    uint32_t want_a = (1u << MFC_SECTORS) - 1, want_b = want_a;
    api->print("reading: checking keys\r\n");
    if (dict_check(r, api, uid32, MFC_KEY_PATH, akey, bkey, &solved, &want_a, &want_b) < 0 ||
        dict_check(r, api, uid32, MFC_DICT_PATH, akey, bkey, &solved, &want_a, &want_b) < 0 ||
        dict_check(r, api, uid32, MFC_CAND_PATH, akey, bkey, &solved, &want_a, &want_b) < 0)
        goto card_lost;
    if (want_a | want_b) goto keys_missing;                /* no usable key for at least one of 16 sectors */

    /* Dump each sector: auth once per keytype (Key A then B) and read the 4 blocks that key can, so access
     * bits that grant read to only one key still yield a full dump. */
    int nsec = 0;
    for (int s = 0; s < MFC_SECTORS; s++) {
        api->printf("reading: sector %d/%d\r\n", s + 1, MFC_SECTORS);
        int base = s * 4;
        uint64_t k2[2] = { akey[s], bkey[s] };
        if (k2[0] != KEY_NONE || k2[1] != KEY_NONE) nsec++;
        uint8_t data[4][16]; int done[4], ndone = 0; for (int i = 0; i < 4; i++) done[i] = 0;
        for (int kt = 0; kt < 2 && ndone < 4; kt++)
            if (k2[kt] != KEY_NONE) read_sector(r, api, uid32, s, kt, k2[kt], data, done, &ndone);

        /* Key B is data, not an authentication key, for trailer access configurations 000/010/001. If Key A
         * exposed it, take the exact six bytes from the trailer—including an all-zero key—rather than trying
         * every dictionary entry against a field which cannot authenticate. Key A is never readable. */
        if (akey[s] != KEY_NONE && bkey[s] == KEY_NONE && done[3]) {
            int c1 = data[3][7] >> 7 & 1, c2 = data[3][8] >> 3 & 1, c3 = data[3][8] >> 7 & 1;
            if (!c1 && !(c2 && c3)) {
                uint64_t key = 0;
                for (int i = 10; i < 16; i++) key = key << 8 | data[3][i];
                bkey[s] = k2[1] = key;
                solved++;
            }
        }

        /* The result promises both sector keys. Search whichever key is still missing even if the primary
         * already read all blocks; if it also unlocks data, retry only the blocks not obtained above. */
        if ((akey[s] != KEY_NONE || bkey[s] != KEY_NONE) &&
            (akey[s] == KEY_NONE || bkey[s] == KEY_NONE)) {
            uint32_t bit = 1u << s;
            want_a = akey[s] == KEY_NONE ? bit : 0;
            want_b = bkey[s] == KEY_NONE ? bit : 0;
            if (dict_check(r, api, uid32, MFC_KEY_PATH, akey, bkey, &solved, &want_a, &want_b) < 0 ||
                dict_check(r, api, uid32, MFC_DICT_PATH, akey, bkey, &solved, &want_a, &want_b) < 0 ||
                dict_check(r, api, uid32, MFC_CAND_PATH, akey, bkey, &solved, &want_a, &want_b) < 0)
                goto card_lost;
            for (int kt = 0; kt < 2 && ndone < 4; kt++) if (k2[kt] == KEY_NONE) {
                k2[kt] = kt ? bkey[s] : akey[s];
                if (k2[kt] != KEY_NONE) {
                    read_sector(r, api, uid32, s, kt, k2[kt], data, done, &ndone);
                }
            }
        }
        if (akey[s] == KEY_NONE || bkey[s] == KEY_NONE) goto keys_missing;
        for (int kt = 0; kt < 2; kt++) {
            k2[kt] = kt ? bkey[s] : akey[s];
            if (k2[kt] != KEY_NONE) print_key(api, s, kt, k2[kt]);
        }
        for (int b = 0; b < 4; b++) {
            char dh[33];
            if (done[b]) { put_hex(dh, data[b], 16); api->printf("mfc: blk %02d = %s\r\n", base + b, dh); }
            else api->printf("mfc: blk %02d = locked\r\n", base + b);
        }
    }

    r->set_mode(FANTASI_RFID_OFF);
    api->print("reading: complete\r\n");
    api->printf("mfc: done %d sectors\r\n", nsec);
    return 1;

card_lost:
    r->set_mode(FANTASI_RFID_OFF);
    api->print("mfc: card lost or unstable response\r\n");
    return 0;

keys_missing:
    r->set_mode(FANTASI_RFID_OFF);
    api->print("mfc: could not recover all 32 keys\r\n");
    return 0;
}
