/* rfid feature module: one MIFARE Classic 1K block (`read mfc -b`).
 *
 * Kept separate from mfc_read so the PM3 never carries single-block machinery
 * while loading the already tight full-card reader. The request and dictionaries
 * are streamed from VFS; no dictionary or card-sized buffer is allocated. */
#include "mfc_common.h"

#define MFC_REQ       "/ramfs/.mfcrreq"   /* "BLOCK" or "BLOCK KEY" */
#define MFC_DICT_PATH "/nfc/mfc.dict"
#define MFC_CAND_PATH "/nfc/mfc_dict.dic"
#define MFC_REC       13

typedef struct { int block, have_key; uint64_t key; } request_t;

static int read_request(const fantasi_api_t *api, request_t *r)
{
    int n = api->file_size(MFC_REQ);
    if (n <= 0 || n >= 32) { api->remove(MFC_REQ); return 0; }
    uint8_t b[32];
    if (api->pread(MFC_REQ, 0, b, (uint32_t)n) != n) {
        api->remove(MFC_REQ); return 0;
    }
    api->remove(MFC_REQ);

    int p = 0, block = 0;
    while (p < n && b[p] >= '0' && b[p] <= '9') block = block * 10 + b[p++] - '0';
    if (p == 0 || block > 63) return 0;
    r->block = block; r->have_key = 0; r->key = 0;
    if (p == n) return 1;
    if (b[p++] != ' ' || n - p != 12 || !mfc_parse_key12(b + p, &r->key)) return 0;
    r->have_key = 1;
    return 1;
}

static int try_auth(const fantasi_rfid_t *r, const fantasi_api_t *api, uint32_t uid,
                    int block, int keytype, uint64_t key, c1_t *cs)
{
    for (int retry = 0; retry < 3; retry++) {
        uint8_t u2[4], s2;
        if (mfc_activate(r, api, u2, &s2, 0) == 0) {
            int rc = mfc_auth(r, uid, (uint8_t)block, keytype, key, cs);
            if (rc != -2) return rc;
        }
    }
    return -2;
}

/* 1 = read, 0 = wrong key/access denied, -1 = card stopped responding. */
static int read_key(const fantasi_rfid_t *r, const fantasi_api_t *api, uint32_t uid,
                    int block, int keytype, uint64_t key, int trusted, uint8_t data[16])
{
    for (int attempt = 0; attempt < (trusted ? 3 : 1); attempt++) {
        c1_t cs;
        int rc = try_auth(r, api, uid, block, keytype, key, &cs);
        if (rc == -2) return -1;
        if (rc != 0) continue;
        if (mfc_read(r, &cs, (uint8_t)block, data) == 0) return 1;
    }
    return 0;
}

static int read_dict(const fantasi_rfid_t *r, const fantasi_api_t *api, uint32_t uid,
                     const char *path, int block, uint64_t *key, int *keytype,
                     uint8_t data[16])
{
    if (api->file_size(path) < 12) return 0;
    for (int i = 0; ; i++) {
        uint8_t rec[12]; uint64_t candidate;
        if (api->pread(path, (uint32_t)i * MFC_REC, rec, sizeof rec) < 12) break;
        if (!mfc_parse_key12(rec, &candidate)) continue;
        for (int kt = 0; kt < 2; kt++) {
            int rc = read_key(r, api, uid, block, kt, candidate, 0, data);
            if (rc < 0) return -1;
            if (rc > 0) { *key = candidate; *keytype = kt; return 1; }
        }
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

int app_main(const fantasi_api_t *api)
{
    const fantasi_rfid_t *r = fantasi_rfid();
    if (!r || !r->hf_transceive_par || !(r->caps() & FANTASI_RFID_CAP_HF_READ)) {
        api->print("mfc: not supported on this device\r\n"); return 0;
    }
    if (!api->pread) { api->print("mfc: firmware has no pread\r\n"); return 0; }
    request_t request;
    if (!read_request(api, &request)) { api->print("mfc: invalid block request\r\n"); return 0; }

    api->print("reading: detecting MIFARE Classic card\r\n");
    if (r->set_mode(FANTASI_RFID_HF_READER) != 0) {
        api->print("mfc: HF frontend unavailable\r\n"); return 0;
    }
    r->field(1); api->delay(10);

    uint8_t uid[4], sak = 0, atqa[2] = {0};
    if (mfc_activate(r, api, uid, &sak, atqa) != 0) goto no_card;
    uint32_t uid32 = be32(uid);
    char uh[9]; put_hex(uh, uid, 4);
    api->printf("mfc: uid=%s sak=%02X atqa=%02X%02X\r\n", uh, sak, atqa[1], atqa[0]);

    /* Match the full reader's stability gate: all five independent nonce
     * exchanges must succeed. This is an exact requirement, never a vote. */
    api->print("reading: profiling card\r\n");
    int nonweak = 0, nsamp = 0; uint32_t nt;
    for (int i = 0; i < 5; i++) {
        if (mfc_get_nt(r, api, &nt) == 0) { nsamp++; if (!is_weak_prng_nonce(nt)) nonweak++; }
        r->field(0); api->delay(2); r->field(1); api->delay(2);
    }
    if (nsamp != 5) goto card_lost;
    api->printf("mfc: prng=%s\r\n", nonweak >= 3 ? "hard" : "weak");

    api->printf("reading: block %d\r\n", request.block);
    uint8_t data[16]; uint64_t used_key = 0; int used_type = 0, rc = 0;
    if (request.have_key) {
        /* -k is authoritative here: do not conceal a wrong explicit key with
         * dictionary fallback. The syntax has no key-type flag, so try A/B. */
        for (int kt = 0; kt < 2 && rc == 0; kt++) {
            rc = read_key(r, api, uid32, request.block, kt, request.key, 1, data);
            if (rc > 0) { used_key = request.key; used_type = kt; }
        }
    } else {
        api->print("reading: checking keys\r\n");
        rc = read_dict(r, api, uid32, MFC_DICT_PATH, request.block,
                       &used_key, &used_type, data);
        if (rc == 0)
            rc = read_dict(r, api, uid32, MFC_CAND_PATH, request.block,
                           &used_key, &used_type, data);
    }
    if (rc < 0) goto card_lost;
    if (rc == 0) {
        r->set_mode(FANTASI_RFID_OFF);
        api->printf(request.have_key ?
                    "mfc: supplied key could not read block %d\r\n" :
                    "mfc: no dictionary key could read block %d\r\n", request.block);
        return 0;
    }

    print_key(api, request.block / 4, used_type, used_key);
    char dh[33]; put_hex(dh, data, 16);
    api->printf("mfc: blk %02d = %s\r\n", request.block, dh);
    r->set_mode(FANTASI_RFID_OFF);
    api->print("reading: complete\r\n");
    api->printf("mfc: done block %d\r\n", request.block);
    return 1;

no_card:
    r->set_mode(FANTASI_RFID_OFF);
    api->print("mfc: no MIFARE Classic card (or 7-byte UID)\r\n");
    return 0;
card_lost:
    r->set_mode(FANTASI_RFID_OFF);
    api->print("mfc: card lost or unstable response\r\n");
    return 0;
}
