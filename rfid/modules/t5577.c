/* rfid feature module: T5577 (ATA5577) LF read/write.
 *
 * Hot-loaded by the rfid driver for `read t5577` / `write t5577`. The private request text is "<block>"
 * with an optional 32-bit hex value; the value's presence picks the operation:
 *   - with data  -> WRITE: pack the "fixed bit length" downlink (opcode 10 page-0, no password + lock
 *                   + 32-bit data + 3-bit block address) and send it via fantasi_rfid()->lf_modulate.
 *   - no data    -> READ:  send the read downlink; the HAL streams the reply as inter-edge run lengths
 *                   (no sample buffer - it demodulates on the fly), and this module reconstructs the
 *                   Manchester half-bits and frames the block. The tag streams the block with no inter-
 *                   copy gap, so the block boundary is resolved from block 0's config structure and reused
 *                   for the target block - the same config.offset approach stock's client uses.
 * Deleted after use, so this ~200-line DSP never sits resident in the tight PM3 driver image. */
#include "t5577_common.h"

#define T5577_REQ  "/ramfs/.t5577req"   /* driver -> module: "<block> [<hex32>]" text */

int app_main(const fantasi_api_t *api)
{
    const fantasi_rfid_t *r = fantasi_rfid();
    if (!r || !r->lf_modulate || !(r->caps() & FANTASI_RFID_CAP_LF_READ)) {
        api->print("t5577: LF not supported on this device\r\n"); return 0;
    }

    char req[48];
    int rn = api->read_file(T5577_REQ, req, sizeof req - 1);
    if (rn < 1) { api->print("t5577: missing block request\r\n"); return 0; }
    req[rn] = '\0';

    const char *p = req;
    while (*p == ' ') p++;
    if (*p < '0' || *p > '7') { api->print("t5577: block must be 0-7\r\n"); return 0; }
    int block = *p++ - '0';

    /* Optional trailing token: `p<0|1>` selects the page for a READ (page 1 holds the traceability + analog
     * option blocks); otherwise any hex is 32-bit WRITE data. Page 1 is read-only here. */
    int page = 0;
    uint32_t data = 0; int nd = 0;
    while (*p == ' ') p++;
    if (*p == 'p' || *p == 'P') {
        p++;
        if ((*p != '0' && *p != '1') || p[1] != '\0') {
            api->print("t5577: page must be p0 or p1\r\n"); return 0;
        }
        page = *p - '0';
    } else {
        for (; *p; p++) {
            int v = hexnib(*p);
            if (v < 0 || nd >= 8) {
                api->print("t5577: data must be exactly 8 hex digits\r\n"); return 0;
            }
            data = (data << 4) | (uint32_t)v;
            nd++;
        }
        if (nd != 0 && nd != 8) {
            api->print("t5577: data must be exactly 8 hex digits\r\n"); return 0;
        }
    }

    if (r->set_mode(FANTASI_RFID_LF_READER) != 0) { api->print("t5577: LF frontend unavailable\r\n"); return 0; }

    if (nd == 0) {                                              /* no data -> READ the block back */
        if (!r->lf_transceive) { r->set_mode(FANTASI_RFID_OFF); api->print("t5577: read not supported\r\n"); return 0; }
        api->printf("reading: T5577 page %d block %d\r\n", page, block);

        /* Ephemeral capture buffer - allocated only for this read, freed before return, so the ~6 KB of raw
         * samples never pins the tight PM3 heap between commands. */
        uint8_t *buf = api->malloc(T55_CAP);
        if (!buf) { r->set_mode(FANTASI_RFID_OFF); api->print("t5577: out of memory\r\n"); return 0; }
        static uint8_t hbit[T55_NHB];

        /* Read the block, self-calibrating the frame off block 0 in the same consecutive read pair (see
         * t55_read_block); reused across both single-block reads here and the whole-tag dump module. */
        uint32_t val = 0;
        int rc = t55_read_block(r, buf, hbit, page, block, &val);
        r->set_mode(FANTASI_RFID_OFF);
        api->free(buf);

        if (rc != 0) { api->print("t5577: read failed (no tag / undecodable)\r\n"); return 0; }
        if (page) api->printf("t5577: block %d page 1 = %08X\r\n", block, (unsigned)val);
        else      api->printf("t5577: block %d = %08X\r\n", block, (unsigned)val);
        return 1;
    }

    /* Pack the WRITE downlink, one byte per bit, MSB-first: opcode(10) lock(0) data[31..0] addr[2..0]. */
    uint8_t bits[38]; int nb = 0;
    bits[nb++] = 1; bits[nb++] = 0;                            /* opcode 10 = page 0 */
    bits[nb++] = 0;                                            /* lock bit */
    for (int i = 31; i >= 0; i--) bits[nb++] = (uint8_t)((data >> i) & 1);
    for (int i = 2;  i >= 0; i--) bits[nb++] = (uint8_t)((block >> i) & 1);

    int rc = r->lf_modulate(bits, nb, 0);
    r->set_mode(FANTASI_RFID_OFF);

    if (rc != 0) { api->print("t5577: write failed\r\n"); return 0; }
    api->printf("t5577: wrote block %d = %08X\r\n", block, (unsigned)data);
    return 1;
}
