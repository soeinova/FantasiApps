/* Shared T5577 (ATA5577) reply DSP - the RF/64 ASK/Manchester demod used by both the single-block
 * read/write module (t5577.c) and the whole-tag `read t5577` dump module (t5577_dump.c). Every helper
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

/* Reconstruct the Manchester half-bit level stream from the HAL's inter-edge run lengths. Legacy streams
 * alternate low, high, low... from index 0. A frontend that needs a fixed capture-time anchor may prefix
 * [0, initial_level]; 0 cannot be a real duration, and the following runs then alternate from that explicit
 * level. The first anchored run may be partial and is allowed to round to zero half-bits. Every later run is
 * round(len / half-bit) half-bits. This does not frame the block - block 0 resolves the rotation, which is
 * then reusable because the anchored stream starts at the same reply phase for every target block. */
static inline int t55_extract(const uint8_t *runs, int nr, uint8_t *hbit, int cap)
{
    int first = 0, level0 = 0, anchored = 0;
    if (nr >= 2 && runs[0] == 0 && runs[1] <= 1) {
        first = 2; level0 = runs[1]; anchored = 1;
    }
    if (nr - first < 2 * T55_NBITS) return -1;          /* need at least ~one block of runs */

    int hbw;
    { int hbsum = 0, hbcnt = 0;
      for (int i = first + anchored; i < nr; i++) {     /* skip an anchored partial first run */
          int r = runs[i];
          if (r >= T55_HB / 2 && r <= (3 * T55_HB) / 2) { hbsum += r; hbcnt++; }
      }
      hbw = hbcnt ? hbsum / hbcnt : T55_HB;
      if (hbw < 20 || hbw > 44) hbw = T55_HB;
    }

    int nhb = 0;
    for (int i = first; i < nr && nhb < cap; i++) {
        int nh = (runs[i] + hbw / 2) / hbw;             /* nearest whole number of half-bits in this run */
        if (nh < 1 && !(anchored && i == first)) nh = 1;
        uint8_t lvl = (uint8_t)(level0 ^ ((i - first) & 1));
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

/* Decode every complete settled repetition at one candidate phase. A trustworthy capture has at least two,
 * every one is valid Manchester, and every one is the same 32-bit word. Return that exact first word only;
 * disagreement is a failed read, never something to repair by selecting or combining bits. Scalar state
 * keeps this check effectively free in RAM on both the Flipper and PM3. */
static inline int t55_stable_at(const uint8_t *hbit, int nhb, int inv, int phase, uint32_t *out)
{
    uint32_t first = 0; int copies = 0;
    for (int k = 1; k <= 3; k++) {                  /* copy 0 may intersect the capture/settle boundary */
        int off = phase + k * T55_PERIOD;
        if (off < 0 || off + T55_PERIOD > nhb) continue;
        uint32_t v;
        if (t55_block(hbit, off, inv, &v) != 0) return -1;
        if (copies && v != first) return -1;
        first = v; copies++;
    }
    if (copies < 2) return -1;
    *out = first;
    return 0;
}

/* Find the block boundary (rotation) of the gapless stream by locking onto block 0's config structure.
 * Only a phase whose settled repetitions agree exactly and decode without Manchester errors may establish
 * the rotation. Returning that exact config also avoids re-decoding it at a nearby phase. */
static inline int t55_find_rot(const uint8_t *hbit, int nhb, int inv, uint32_t *cfg)
{
    for (int rot = 0; rot < T55_PERIOD; rot++) {
        uint32_t v;
        if (t55_stable_at(hbit, nhb, inv, rot, &v) == 0 && t55_valid_cfg(v)) {
            if (cfg) *cfg = v;
            return rot;
        }
    }
    return -1;
}

/* Decode a data block only when its complete settled repetitions agree. A fixed-time anchored stream uses the
 * exact calibrated phase. Legacy edge-anchored frontends may need their historical +/- half-bit correction
 * because the first run can merge differently between config and data; each candidate correction must still
 * pass the same zero-error agreement rule. Prefer the calibrated phase, then the two adjacent phases. */
static inline int t55_decode_rot(const uint8_t *hbit, int nhb, int inv, int rot, int anchored, uint32_t *out)
{
    int tries = anchored ? 1 : 3;
    for (int pass = 0; pass < tries; pass++) {
        int d = pass == 0 ? 0 : (pass == 1 ? -1 : 1);
        if (t55_stable_at(hbit, nhb, inv, rot + d, out) == 0) return 0;
    }
    return -1;
}

/* Read one block, self-calibrating the gapless reply's whole-bit rotation from block 0 immediately before the
 * target. A fixed-time anchored frontend transfers that exact rotation; a legacy edge-anchored frontend gets
 * the small phase correction in t55_decode_rot. For block 0 the exact repeated calibration word is the answer.
 * `buf` (>= T55_CAP) / `hbit` (>= T55_NHB) are reused scratch. Returns 0 and writes *out only when repeated
 * copies are stable, or a negative value on no tag / unstable capture / framing failure. */
static inline int t55_read_block(const fantasi_rfid_t *r, uint8_t *buf, uint8_t *hbit,
                                 int page, int block, uint32_t *out)
{
    uint8_t cmd0[6] = { 1, (uint8_t)page, 0, 0, 0, 0 };     /* calibrate on block 0 of the target's page (block 0
                                                            * aliases the config on both pages) so calib + target
                                                            * share the page - and, on platforms that align the
                                                            * downlink per-page, the same alignment/capture phase. */
    int n0 = r->lf_transceive(cmd0, 6, buf, T55_CAP);
    if (n0 <= 0) return n0 ? n0 : -10;
    int anchored0 = n0 >= 2 && buf[0] == 0 && buf[1] <= 1;
    int nhb0 = t55_extract(buf, n0, hbit, T55_NHB);
    if (nhb0 <= 0) return -11;
    uint32_t cfg = 0;
    int inv = 1, rot = (nhb0 > 0) ? t55_find_rot(hbit, nhb0, inv, &cfg) : -1;
    if (rot < 0 && nhb0 > 0) { inv = 0; rot = t55_find_rot(hbit, nhb0, inv, &cfg); } /* other Manchester sense */
    if (rot < 0) return -12;
    if (page == 0 && block == 0) { *out = cfg; return 0; }

    uint8_t cmd[6] = { 1, (uint8_t)page, 0,                 /* opcode bit 2 = page (10 = p0, 11 = p1) */
                       (uint8_t)((block >> 2) & 1),
                       (uint8_t)((block >> 1) & 1),
                       (uint8_t)(block & 1) };
    int n = r->lf_transceive(cmd, 6, buf, T55_CAP);
    if (n <= 0) return n ? n : -20;
    int anchored = n >= 2 && buf[0] == 0 && buf[1] <= 1;
    int nhb = t55_extract(buf, n, hbit, T55_NHB);
    if (nhb <= 0) return -21;

    /* Anchored streams decode at the exact phase; legacy streams retain their small edge-merge correction. */
    return t55_decode_rot(hbit, nhb, inv, rot, anchored0 && anchored, out);
}

#endif /* RFID_T5577_COMMON_H */
