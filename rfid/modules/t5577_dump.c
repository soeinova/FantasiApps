/* rfid feature module: T5577 (ATA5577) whole-tag dump (bare `read t5577`).
 *
 * This module does the whole tag in one invocation: provision once, then read every
 * physical block. It prints one line per block, `t5577: p<page> b<block> = <8hex|-------->`, which the
 * host parses into the themed dump box.
 *
 * Each block is read via t55_read_block, which self-calibrates the block boundary off block 0 in the same
 * consecutive read pair - reusing one distant calibration across many reads shifts the whole value by a bit,
 * because the reply frame anchor lands a full bit differently between non-adjacent reads.
 * A field-off reset between blocks keeps the tag from staying latched on a prior block. Page 0 = blocks 0-7
 * (block 0 config, 1-7 user). Page 1 = blocks 1-3 (1-2 traceability, 3 analog option). Shares the RF/64
 * ASK/Manchester reply DSP with t5577.c via t5577_common.h. Deleted after use. */
#include "t5577_common.h"

/* Between blocks the tag must fully power down so the next read's calibration lands cleanly and it isn't
 * still modulating a prior block. `lf_transceive` only drops the field microseconds at exit, and the 8 ms
 * charge doesn't clear tag state - so a field-off gap here drains it (the single-block module gets this for
 * free from the seconds-long gap between its separate invocations). */
#define T55_RESET_MS 20

int app_main(const fantasi_api_t *api)
{
    const fantasi_rfid_t *r = fantasi_rfid();
    if (!r || !r->lf_modulate || !(r->caps() & FANTASI_RFID_CAP_LF_READ)) {
        api->print("t5577: LF not supported on this device\r\n"); return 0;
    }
    if (!r->lf_transceive) { api->print("t5577: read not supported\r\n"); return 0; }
    api->print("reading: detecting T5577 card\r\n");
    if (r->set_mode(FANTASI_RFID_LF_READER) != 0) { api->print("t5577: LF frontend unavailable\r\n"); return 0; }

    /* Ephemeral capture buffer - freed before return, so the raw samples never pin the tight PM3 heap. */
    uint8_t *buf = api->malloc(T55_CAP);
    if (!buf) { r->set_mode(FANTASI_RFID_OFF); api->print("t5577: out of memory\r\n"); return 0; }
    static uint8_t hbit[T55_NHB];

    /* Physical blocks to dump, in order: page 0 blocks 0-7, then page 1 blocks 1-3. */
    static const uint8_t PG[11] = { 0,0,0,0,0,0,0,0, 1,1,1 };
    static const uint8_t BK[11] = { 0,1,2,3,4,5,6,7, 1,2,3 };

    uint32_t v;
    int framed = 0;
    for (int i = 0; i < 11; i++) {
        api->printf("reading: block %d/11\r\n", i + 1);
        api->delay(T55_RESET_MS);                          /* drain/reset the tag before this block's read */
        int rc = t55_read_block(r, buf, hbit, PG[i], BK[i], &v);
        if (rc == 0) { framed = 1; api->printf("t5577: p%d b%d = %08X\r\n", PG[i], BK[i], (unsigned)v); }
        else                       api->printf("t5577: p%d b%d = --------\r\n", PG[i], BK[i]);
        if (i == 0 && !framed) {                           /* block 0 unframable -> no tag / not a T5577 */
            r->set_mode(FANTASI_RFID_OFF); api->free(buf);
            api->print("t5577: read failed (no tag / can't frame config block)\r\n"); return 0;
        }
    }

    r->set_mode(FANTASI_RFID_OFF);
    api->free(buf);
    api->print("reading: complete\r\n");
    return 1;
}
