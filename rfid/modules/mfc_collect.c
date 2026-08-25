/* rfid feature module: MIFARE Classic nonce collect (`collect mfc card`).
 *
 * Searches for a MIFARE Classic, bootstraps one known key (built-in defaults, or the host -k key), then for
 * each still-unknown Key A / Key B slot harvests nested nonces the way Flipper's hardnested collector does:
 * keep collecting until all 256 distinct nt_enc MSB bytes have appeared, printing every collected nonce (in
 * the exact Flipper `.nested.log` hardnested format) to the host session, framed by NONCE-BEGIN/END. The host
 * CLI captures the cloud and feeds an offline solver (hardnested_main); nothing is written to device flash.
 *
 * We emit the whole ~1500-nonce cloud, not one nonce per first byte: the solver's per-first-byte a8-sum and
 * bitflip-parity analysis need ~6 nonces per first byte - a single nonce per byte gives it nothing to work
 * with and never resolves a key. Flipper buffers the cloud in RAM and writes at the end; the PM3 heap can't,
 * so we stream each nonce as it arrives (the 256-distinct-MSB counter only gates completion). We print rather
 * than write /nfc/mfc.log because a LittleFS write mid-collect stalls the RF timing and craters the nested-
 * auth hit rate. The per-MSB parity sum is reported for sanity but not enforced - the solver validates it.
 * Weak-PRNG cards need a 2-nonce pair + timing calibration to log plaintext nt/dist - not yet ported. */
#include "mfc_common.h"

#define MFC_CFG_PATH "/ramfs/mfc_cfg"
#define MSB_TARGET   256                 /* all 256 distinct nt_enc MSB bytes (Flipper msb_count == UINT8_MAX+1) */
#define MAX_COLLECT  6000                /* safety cap on nonces per target (coupon-collector expects ~1.5k) */

/* The valid Hardnested per-MSB parity sums (Flipper valid_sums / is_valid_sum). */
static const uint16_t valid_sums[19] =
    { 0, 32, 56, 64, 80, 96, 104, 112, 120, 128, 136, 144, 152, 160, 176, 192, 200, 224, 256 };
static int is_valid_sum(uint16_t s) { for (int i = 0; i < 19; i++) if (s == valid_sums[i]) return 1; return 0; }

/* tiny string builders (the module loader can't resolve libc snprintf / __aeabi_idivmod / memset) */
static char *put_str(char *d, const char *s) { while (*s) *d++ = *s++; return d; }
static char *put_dec(char *d, int v) { char t[8]; int n = 0; if (v == 0) t[n++] = '0';
    while (v > 0) { int r = v, q = 0; while (r >= 10) { r -= 10; q++; } t[n++] = (char)('0' + r); v = q; } while (n) *d++ = t[--n]; return d; }
static char *put_hex8(char *d, uint32_t v) { uint8_t b[4] = { (uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v }; put_hex(d, b, 4); return d + 8; }

int app_main(const fantasi_api_t *api)
{
    const fantasi_rfid_t *r = fantasi_rfid();
    if (!r || !r->hf_transceive_par || !(r->caps() & FANTASI_RFID_CAP_HF_READ)) {
        api->print("collect: not supported on this device\r\n"); return 0;
    }
    if (!api->append) { api->print("collect: firmware has no append primitive\r\n"); return 0; }

    uint8_t cfg[14]; for (int i = 0; i < 14; i++) cfg[i] = 0;
    int have_key = 0; uint64_t cfg_key = 0;
    if (api->read_file(MFC_CFG_PATH, cfg, sizeof cfg) >= 8) {
        have_key = cfg[0] & 1;
        for (int i = 0; i < 6; i++) cfg_key = cfg_key << 8 | cfg[1 + i];
    }
    api->remove(MFC_CFG_PATH);                    /* parsed: release the RAMFS staging file before RF work */

    if (r->set_mode(FANTASI_RFID_HF_READER) != 0) { api->print("collect: HF frontend unavailable\r\n"); return 0; }
    r->field(1);
    api->delay(10);                       /* match search/read card power-up before the first WUPA */

    uint8_t uid[4], sak = 0, atqa[2] = {0};
    if (mfc_activate(r, api, uid, &sak, atqa) != 0) {
        r->set_mode(FANTASI_RFID_OFF);
        api->print("collect: no MIFARE Classic found\r\n"); return 0;
    }
    uint32_t uid32 = be32(uid);
    char uh[9]; put_hex(uh, uid, 4);
    api->printf("collect: found MIFARE Classic uid=%s sak=%02X atqa=%02X%02X\r\n", uh, sak, atqa[1], atqa[0]);

    int nonweak = 0, nsamp = 0; uint32_t nt;
    for (int i = 0; i < 5; i++) {
        if (mfc_get_nt(r, api, &nt) == 0) { nsamp++; if (!is_weak_prng_nonce(nt)) nonweak++; }
        /* mfc_get_nt deliberately stops after AUTH's nonce, leaving the card in
         * its crypto handshake. Reset it before the next independent sample. */
        r->field(0); api->delay(2); r->field(1); api->delay(2);
    }
    int hard = (nonweak >= 3);
    if (nsamp && !hard) { r->set_mode(FANTASI_RFID_OFF);
        api->print("collect: weak-PRNG nonce logging needs timing calibration (not implemented yet)\r\n"); return 0; }

    /* bootstrap one known key (built-in defaults + host -k), tried in every empty slot */
    uint64_t akey[MFC_SECTORS], bkey[MFC_SECTORS];
    for (int i = 0; i < MFC_SECTORS; i++) akey[i] = bkey[i] = KEY_NONE;
    uint64_t known_key = 0; int known_sec = -1, known_type = 0;
    for (int ki = 0; ki <= MFC_NBOOT; ki++) {
        uint64_t key = (ki < MFC_NBOOT) ? MFC_BOOT_KEYS[ki] : (have_key ? cfg_key : KEY_NONE);
        if (key == KEY_NONE) continue;
        for (int s = 0; s < MFC_SECTORS; s++) for (int kt = 0; kt < 2; kt++) {
            uint64_t *slot = kt ? &bkey[s] : &akey[s];
            if (*slot != KEY_NONE) continue;
            uint8_t u2[4], s2; c1_t cs;
            if (mfc_activate(r, api, u2, &s2, 0) != 0) continue;
            if (mfc_auth(r, uid32, (uint8_t)(s * 4), kt, key, &cs) == 0) {
                *slot = key; if (known_sec < 0) { known_key = key; known_sec = s; known_type = kt; }
            }
        }
    }
    if (known_sec < 0) { r->set_mode(FANTASI_RFID_OFF); api->print("collect: no known key (try -k)\r\n"); return 0; }

    int total = 0;
    for (int s = 0; s < MFC_SECTORS && known_sec >= 0; s++) for (int kt = 0; kt < 2; kt++) {
        if ((kt ? bkey[s] : akey[s]) != KEY_NONE) continue;   /* already known - no nonces needed */
        uint8_t target = (uint8_t)(s * 4 + 3);
        uint8_t msb[32]; for (int i = 0; i < 32; i++) msb[i] = 0;
        int seen = 0, sum = 0, got = 0, logged = 0;
        char lbuf[512]; int lo = 0;
        /* print every collected nonce (not one per first byte) straight to the host session, framed by
         * NONCE-BEGIN/END so the host CLI can capture the cloud and hand it to an offline solver. Two reasons
         * not to write /nfc/mfc.log on-device: (1) a LittleFS write mid-collect stalls the RF timing and
         * craters the nested-auth hit rate; (2) hardnested needs the whole ~1500-nonce cloud (~6 per first
         * byte) for its a8-sum + bitflip analysis - one-per-byte is unsolvable - and that won't fit flash.
         * Stop once all 256 first-byte values have appeared (coupon-collector completion, ~1500 nonces). */
        api->printf("NONCE-BEGIN sec %d key %c\r\n", s, kt ? 'B' : 'A');
        while (seen < MSB_TARGET && got < MAX_COLLECT) {
            uint32_t ne; uint8_t pk;
            if (mfc_collect_nested(r, api, uid32, (uint8_t)(known_sec * 4), known_type, known_key,
                                   target, kt, &ne, &pk) != 0) { got++; continue; }
            got++;
            uint8_t m = (uint8_t)(ne >> 24);
            if (!(msb[m >> 3] & (1 << (m & 7)))) {             /* first sighting of this first byte */
                msb[m >> 3] |= (uint8_t)(1 << (m & 7)); seen++;
                sum += (pk >> 3) & 1;                          /* msb_par_sum: top parity bit, per unique MSB */
            }
            char *p = lbuf + lo;                               /* Flipper .nested.log line (hardnested variant) */
            p = put_str(p, "Sec "); p = put_dec(p, s);
            p = put_str(p, " key "); *p++ = kt ? 'B' : 'A';
            p = put_str(p, " cuid "); p = put_hex8(p, uid32);
            p = put_str(p, " nt0 00000000 ks0 "); p = put_hex8(p, ne);   /* nt=0 (hard), ks0 = raw nt_enc */
            p = put_str(p, " par0 ");
            uint8_t parb = (uint8_t)(pk ^ 0x0F);               /* raw transmitted parity, byte0 at bit3 */
            for (int b = 0; b < 4; b++) *p++ = (char)('0' + ((parb >> (3 - b)) & 1));
            *p++ = '\n';
            lo = (int)(p - lbuf);
            if (lo > (int)sizeof lbuf - 96) { lbuf[lo] = 0; api->print(lbuf); lo = 0; }   /* print, not flash */
            logged++;
        }
        if (lo) { lbuf[lo] = 0; api->print(lbuf); }
        api->print("NONCE-END\r\n");
        total += logged;
        api->printf("collect: sec %d key %c %s - %d nonces sum %d%s\r\n", s, kt ? 'B' : 'A',
                    (seen == MSB_TARGET) ? "collected" : "incomplete", logged, sum,
                    is_valid_sum((uint16_t)sum) ? "" : " (bad sum, re-run)");
    }

    r->set_mode(FANTASI_RFID_OFF);
    api->printf("collect: streamed %d nonce(s)\r\n", total);
    return 1;
}
