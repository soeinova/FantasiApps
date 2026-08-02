/* rfid feature module: raw ISO14443-A frame TX/RX.
 *
 * One of the modules the rfid driver (rfid.c) hot-loads into RAM - resident only
 * while a `raw` command runs. Reads the driver's request from RAW_REQ (flags +
 * the frame), drives the ST25R3916 reader through the loader-resolved
 * fantasi_rfid() table, and writes the exchanged frames to RAW_LAST for the
 * driver to display and fold into the running trace. Every transceive goes
 * through raw_txrx() (raw.h) so it is logged. Like pm3's `hf 14a raw`: -c appends
 * CRC_A, -s selects the card first, -k leaves the field on for follow-ups. */
#include "app_api.h"
#include "app_rfid.h"
#include "raw.h"

/* One anticollision cascade level: ANTICOLL (sel 20) then SELECT (sel 70 + the
 * echoed anticoll response + CRC). Echoing the response into SELECT means we need
 * no UID-structure knowledge (cascade tag, BCC handling is transparent). Returns
 * the SAK byte, or -1. The card's cascade bit (SAK & 0x04) says whether another
 * level follows. */
static int anticoll_level(rawtrace_t *t, const fantasi_rfid_t *r, uint8_t sel)
{
    uint8_t rx[16];
    uint8_t ac[2] = { sel, 0x20 };
    if (raw_txrx(t, r, ac, 16, 0, rx, sizeof rx) < 40) return -1;   /* -> CT/UID + BCC (5 bytes) */

    uint8_t s[9] = { sel, 0x70, rx[0], rx[1], rx[2], rx[3], rx[4] };
    uint16_t c = raw_crc(s, 7); s[7] = (uint8_t)c; s[8] = (uint8_t)(c >> 8);
    uint8_t sak[8];
    if (raw_txrx(t, r, s, 72, 0, sak, sizeof sak) < 8) return -1;   /* -> SAK + CRC (3 bytes) */
    return sak[0];
}

/* Full activation: WUPA, then anticollision/select up the cascade until the card
 * stops setting the cascade bit. Returns 0 on success, -1 if no card / error.
 * WUPA is retried a few times (probe without logging the misses) - straight after a
 * cold reader re-init (e.g. the first raw following a sniff) the card can take a
 * couple ms extra to power up, and a single WUPA would spuriously report no tag. */
static int activate(rawtrace_t *t, const fantasi_rfid_t *r, const fantasi_api_t *api)
{
    uint8_t rx[16], wupa = 0x52;
    int rb = -1;
    for (int i = 0; i < 4; i++) {
        rb = r->hf_transceive(&wupa, 7, 0, rx, sizeof rx, 0);
        if (rb >= 0) break;
        api->delay(3);
    }
    raw_log(t, 'R', &wupa, 1);                         /* log WUPA (the successful, or lone failed, attempt) */
    if (rb < 0) return -1;
    raw_log(t, 'C', rx, (rb + 7) / 8);                 /* -> ATQA */

    static const uint8_t sel[3] = { 0x93, 0x95, 0x97 };
    for (int lvl = 0; lvl < 3; lvl++) {
        int sak = anticoll_level(t, r, sel[lvl]);
        if (sak < 0) return -1;
        if (!(sak & 0x04)) return 0;   /* cascade complete */
    }
    return -1;
}

int app_main(const fantasi_api_t *api)
{
    const fantasi_rfid_t *r = fantasi_rfid();
    if (!r || !(r->caps() & FANTASI_RFID_CAP_HF_READ)) return 0;

    uint8_t req[80];
    int rn = api->read_file(RAW_REQ, req, sizeof req);
    if (rn < 2) return 0;
    uint32_t flags = req[0];
    int nbytes = req[1];
    if (nbytes > rn - 2) nbytes = rn - 2;
    if (nbytes > 64) nbytes = 64;

    /* set_mode is idempotent, so a -k field kept on by a previous raw command is
     * not disturbed here - the card stays powered/selected across commands. */
    if (r->set_mode(FANTASI_RFID_HF_READER) != 0) return 0;
    r->field(1);
    api->delay(10);                       /* field settle / card power-up (esp. a cold reader re-init) */

    static char tbuf[1024];
    rawtrace_t t = { tbuf, 0, sizeof tbuf };
    uint8_t rx[256];

    if (flags & RAW_F_SELECT) activate(&t, r, api);

    if (nbytes > 0) {
        uint8_t tx[70]; int tn = 0;
        for (int i = 0; i < nbytes; i++) tx[tn++] = req[2 + i];
        if (flags & RAW_F_CRC) { uint16_t c = raw_crc(tx, tn); tx[tn++] = (uint8_t)c; tx[tn++] = (uint8_t)(c >> 8); }
        raw_txrx(&t, r, tx, tn * 8, 0, rx, sizeof rx);
    }

    if (!(flags & RAW_F_KEEP)) { r->field(0); r->set_mode(FANTASI_RFID_OFF); }

    api->write_file(RAW_LAST, t.buf, (uint32_t)t.len);
    return 1;
}
