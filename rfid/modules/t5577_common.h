/* Shared T5577 (ATA5577) reply DSP - the RF/64 ASK/Manchester demod used by both the single-block
 * `raw t5577` module (t5577.c) and the whole-tag `read t5577` dump module (t5577_dump.c). Every helper
 * is `static inline` so each includer keeps only the primitives it calls (--gc-sections trims the rest,
 * with no unused-function warnings). The HAL streams the reply as inter-edge run lengths (no sample
 * buffer); this reconstructs the Manchester half-bits and frames a block via block 0's config.offset. */
#ifndef RFID_T5577_COMMON_H
#define RFID_T5577_COMMON_H

#include "app_api.h"
#include "app_rfid.h"

#define T55_HB     32       /* half-bit width, in carrier cycles (RF/64: 32 cycles per half-bit) */
#define T55_NBITS  32       /* one block */
#define T55_PERIOD (2 * T55_NBITS)   /* one block = 64 half-bits; the reply repeats at this period */
#define T55_CAP    256      /* max inter-edge run lengths captured (streamed, ~1-2 bytes each) - a few
                             * hundred bytes, not KB of samples: no heap pressure, and covers several copies */
#define T55_NHB    288      /* reconstructed half-bit levels: ~4 block copies for robust config framing */
#define T55_ROT_MAX_ERR 6   /* Manchester errors tolerated when locking the rotation (see t55_find_rot) */

/* Manchester-decode one 32-bit block from the half-bit levels starting at `off` (10/01 -> the two values,
 * an equal pair is a Manchester error). MSB-first, `inv` picks the high=1 vs high=0 convention. Returns
 * the error count; writes the word to *v. */
static inline int t55_block(const uint8_t *hb, int off, int inv, uint32_t *v)
{
    uint32_t val = 0; int err = 0;
    for (int b = 0; b < T55_NBITS; b++) {
        int a = hb[off + 2 * b], c = hb[off + 2 * b + 1], bt;
        if (a == 1 && c == 0) bt = 0; else if (a == 0 && c == 1) bt = 1; else { err++; bt = c; }
        val = (val << 1) | (uint32_t)(bt ^ inv);
    }
    *v = val; return err;
}

static inline int hexnib(char c)
{ return (c >= '0' && c <= '9') ? c - '0'
       : (c >= 'a' && c <= 'f') ? c - 'a' + 10
       : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1; }

/* Reconstruct the Manchester half-bit level stream from the HAL's inter-edge run lengths (`runs[0..nr]`,
 * alternating low, high, low... from the first falling edge = the gap->block transition), writing to `hbit`
 * and returning the count. Each run is round(len / half-bit) half-bits of its level. The half-bit width is
 * estimated from the reply's own single-half-bit runs (the shortest common run near RF/64's 32-cycle half-
 * bit). This does not frame the block - the boundary (rotation) within the gapless repeating stream is
 * resolved from block 0's config structure (config.offset), as stock does. Returns the count, or -1. */
static inline int t55_extract(const uint8_t *runs, int nr, uint8_t *hbit, int cap)
{
    if (nr < 2 * T55_NBITS) return -1;                  /* need at least ~one block of runs */

    int hbw;
    { int hbsum = 0, hbcnt = 0;
      for (int i = 0; i < nr; i++) {                    /* single half-bit runs cluster near the half-bit */
          int r = runs[i];
          if (r >= T55_HB / 2 && r <= (3 * T55_HB) / 2) { hbsum += r; hbcnt++; }
      }
      hbw = hbcnt ? hbsum / hbcnt : T55_HB;
      if (hbw < 20 || hbw > 44) hbw = T55_HB;
    }

    int nhb = 0;
    for (int i = 0; i < nr && nhb < cap; i++) {
        int nh = (runs[i] + hbw / 2) / hbw;             /* nearest whole number of half-bits in this run */
        if (nh < 1) nh = 1;
        uint8_t lvl = (uint8_t)((i & 1) ? 1 : 0);       /* runs alternate low(0), high(1) from index 0 */
        for (int k = 0; k < nh && nhb < cap; k++) hbit[nhb++] = lvl;
    }
    return nhb;
}

/* True if `b` is a plausible T55x7 basic-mode block-0 config for our RF/64 tag: master-key nibble in
 * {0,6,9}, the basic-mode fixed-0 bits clear, a defined modulation field, and the data bit rate == RF/64.
 * Ported from proxmark3 client t55xx_is_valid_block0 (cmdlft55xx.c). Only the correct block boundary makes
 * block 0 satisfy all of these, so this is what pins the rotation of the gapless stream. */
static inline int t55_valid_cfg(uint32_t b)
{
    if (b == 0) return 0;
    uint32_t mk = (b >> 28) & 0xF;
    if (mk != 0x0 && mk != 0x6 && mk != 0x9) return 0;
    if (((b >> 17) & 1) && (mk == 0x6 || mk == 0x9)) { if ((b & 0x0F000000u) != 0) return 0; }   /* X mode */
    else                                             { if ((b & 0x0FE00106u) != 0) return 0; }   /* basic  */
    uint32_t mod = (b >> 12) & 0x1F;
    if (mod > 0x08 && mod != 0x10 && mod != 0x18) return 0;                     /* defined modulation field */
    if (((b >> 17) & 1) && (mk == 0x6 || mk == 0x9))                            /* data rate == RF/64 */
        return ((b >> 18) & 0x3F) == 31;                                        /* X mode: 31*2+2 == 64 */
    return ((b >> 18) & 0x7) == 5;                                              /* basic mode: index 5 == 64 */
}

/* Find the block boundary (rotation) of the gapless stream by locking onto block 0's config structure:
 * slide the offset across a full block period and return the one where a settled copy decodes to a valid
 * config. This is stock's config.offset - the rotation is deterministic for a tag, so it's calibrated once
 * from block 0 and reused for every block. Returns the half-bit rotation, or -1. */
static inline int t55_find_rot(const uint8_t *hbit, int nhb, int inv)
{
    /* Take the lowest-error rotation that yields a valid config, not merely the first error-free one. A
     * handful of Manchester errors is normal on a marginal envelope (a stretched run decodes as a third
     * consecutive half-bit, which Manchester cannot express). t55_valid_cfg is the real gate - master key,
     * basic-mode reserved bits, a defined modulation field and the RF/64 data rate all have to agree, which
     * a wrong rotation does not manage by chance - so the error count only has to break ties. */
    int best_rot = -1, best_err = T55_ROT_MAX_ERR + 1;
    for (int rot = 0; rot < T55_PERIOD; rot++)
        for (int k = 1; k <= 2; k++) {              /* copies 1-2: past the first copy's settling-noisy MSB */
            int off = rot + k * T55_PERIOD;
            if (off + T55_PERIOD > nhb) continue;
            uint32_t v; int e = t55_block(hbit, off, inv, &v);
            if (e < best_err && t55_valid_cfg(v)) { best_err = e; best_rot = rot; }
        }
    return best_rot;
}

/* Decode the 32-bit block at a known rotation from the cleanest settled copy (skip copy 0, whose MSB is
 * corrupted while the peak detector settles). The rotation was calibrated on block 0, whose MSB polarity
 * can merge into the flat gap one half-bit differently than this block's, so search +-1 half-bit around it
 * and keep the lowest-error Manchester phase (the full-bit aliases sit +-2 away, outside the window). No
 * averaging - just the single cleanest settled copy. */
static inline int t55_decode_rot(const uint8_t *hbit, int nhb, int inv, int rot, uint32_t *out)
{
    /* Lowest Manchester error wins; on a tie prefer the offset closest to the calibrated rot (smallest |d|).
     * A constant all-0/all-1 block is a phase-ambiguous square wave - every half-bit offset decodes error-
     * free, one phase to all-0 and its neighbour to all-1 - so without this tie-break it can invert (an empty
     * 00000000 block read as FFFFFFFF). d==0 keeps block 0's calibrated phase, which is the tag's true phase;
     * a genuine full-frame slip on a structured block still wins via strictly-lower error at d=+-1. */
    int be = 1 << 30, bd = 99, found = 0; uint32_t bv = 0;
    for (int k = 1; k <= 3; k++)
        for (int d = -1; d <= 1; d++) {
            int off = rot + d + k * T55_PERIOD;
            if (off < 0 || off + T55_PERIOD > nhb) continue;
            uint32_t v; int e = t55_block(hbit, off, inv, &v);
            int ad = d < 0 ? -d : d;
            if (e < be || (e == be && ad < bd)) { be = e; bd = ad; bv = v; found = 1; }
        }
    if (!found) return -1;
    *out = bv;
    return 0;
}

/* Read one block, self-calibrating the block boundary off block 0 in the same read pair. The gapless reply
 * is ambiguous by whole-bit rotations, resolved stock's way (config.offset): read block 0, find the rotation
 * at which it decodes to a valid config, then read the target consecutively and decode at that rotation. The
 * two reads must be consecutive - the reply's frame anchor (the gap->block edge) lands a full bit differently
 * between non-adjacent reads, and a stale rotation from a distant calibration shifts the whole value by a bit.
 * For block 0 the calibration read is the answer. `buf` (>= T55_CAP) / `hbit` (>= T55_NHB) are reused scratch.
 * Returns 0 and writes *out on a clean decode; -1 on no tag / unframable. */
static inline int t55_read_block(const fantasi_rfid_t *r, uint8_t *buf, uint8_t *hbit,
                                 int page, int block, uint32_t *out)
{
    uint8_t cmd0[6] = { 1, (uint8_t)page, 0, 0, 0, 0 };     /* calibrate on block 0 of the target's page (block 0
                                                            * aliases the config on both pages) so calib + target
                                                            * share the page - and, on platforms that align the
                                                            * downlink per-page, the same alignment/capture phase. */
    int n0 = r->lf_transceive(cmd0, 6, buf, T55_CAP);
    int nhb0 = (n0 > 0) ? t55_extract(buf, n0, hbit, T55_NHB) : -1;
    int inv = 1, rot = (nhb0 > 0) ? t55_find_rot(hbit, nhb0, inv) : -1;
    if (rot < 0 && nhb0 > 0) { inv = 0; rot = t55_find_rot(hbit, nhb0, inv); }   /* other Manchester sense */
    if (rot < 0) return -1;
    if (page == 0 && block == 0) return t55_decode_rot(hbit, nhb0, inv, rot, out);

    uint8_t cmd[6] = { 1, (uint8_t)page, 0,                 /* opcode bit 2 = page (10 = p0, 11 = p1) */
                       (uint8_t)((block >> 2) & 1),
                       (uint8_t)((block >> 1) & 1),
                       (uint8_t)(block & 1) };
    int n = r->lf_transceive(cmd, 6, buf, T55_CAP);
    int nhb = (n > 0) ? t55_extract(buf, n, hbit, T55_NHB) : -1;

    /* No phase correction needed: the HAL locks every capture's anchor to the same gap->block position
     * (see lf_demod_t55), so a target reply frames identically to the block-0 calibration. */
    return (nhb > 0) ? t55_decode_rot(hbit, nhb, inv, rot, out) : -1;
}

#endif /* RFID_T5577_COMMON_H */
