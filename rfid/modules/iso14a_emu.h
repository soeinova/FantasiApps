/* Shared ISO14443-A tag-side response encoding for emulation modules.
 *
 * The HAL (hf_emu_send) does only the real-time bit I/O + FDT; the tag reply must arrive pre-encoded as one
 * byte per subcarrier symbol. This header turns a response frame (bytes + parity) into that ToSend buffer,
 * reusable by any 14443-A tag emulation (MIFARE Classic, Ultralight, NTAG, ...). Port of the ToSend build in
 * proxmark3 armsrc/iso14443a.c CodeIso14443aAsTagPar. Pulls in mfc_common.h for oddparity8/crc_a. */
#ifndef FANTASI_RFID_ISO14A_EMU_H
#define FANTASI_RFID_ISO14A_EMU_H

#include "mfc_common.h"

/* tag->reader subcarrier symbols: one byte drives one bit-period of load modulation in the FPGA. */
#define TAG_SEC_D 0xf0      /* logic 1 (modulation in the first half-bit)  */
#define TAG_SEC_E 0x0f      /* logic 0 (modulation in the second half-bit) */
#define TAG_SEC_F 0x00      /* stop bit / idle (no modulation)             */

/* Odd-parity array for a plaintext frame, MSB-first: bit (7-(i&7)) of par[i>>3] = odd parity of byte i.
 * (Encrypted frames get their parity from mf-crypto1 encryption instead.) `par` needs (n+7)/8 bytes. */
static inline void iso14a_parity(const uint8_t *d, int n, uint8_t *par)
{
    for (int i = 0; i < n; i++) {
        if ((i & 7) == 0) par[i >> 3] = 0;
        par[i >> 3] |= (uint8_t)(oddparity8(d[i]) << (7 - (i & 7)));
    }
}

/* Encode a tag response into the ToSend symbol buffer `ts` (needs >= 3 + 9*len bytes) and return the symbol
 * count. Layout: [0] 8-bit correction template 00001000 (hf_emu_send keeps or drops it per the last received
 * bit -> 1236 vs 1172 FDT), [1] start bit, then per data bit a SEC_D/SEC_E symbol LSB-first with a parity
 * symbol after every byte, then a stop symbol. `par` is the MSB-first parity array. */
static inline int iso14a_tag_encode(const uint8_t *d, int len, const uint8_t *par, uint8_t *ts)
{
    int m = 0;
    ts[m++] = 0x08;                 /* correction template (00001000) */
    ts[m++] = TAG_SEC_D;            /* start bit */
    for (int i = 0; i < len; i++) {
        uint8_t b = d[i];
        for (int j = 0; j < 8; j++) { ts[m++] = (b & 1) ? TAG_SEC_D : TAG_SEC_E; b >>= 1; }
        ts[m++] = (par[i >> 3] & (0x80 >> (i & 7))) ? TAG_SEC_D : TAG_SEC_E;
    }
    ts[m++] = TAG_SEC_F;            /* stop bit */
    return m;
}

/* Encrypt `len` plaintext bytes in place with the running Crypto1 cipher and fill the MSB-first encrypted
 * parity array `par`. Port of mifareutil.c mf_crypto1_encryptEx (keystream = c1_byte(feed 0); the parity
 * keystream bit is filter(odd) taken after the byte, XORed with the plaintext byte's odd parity). */
static inline void mf_crypto1_encrypt(c1_t *pcs, uint8_t *data, int len, uint8_t *par)
{
    for (int i = 0; i < len; i++) {
        uint8_t bt = data[i];
        data[i] = c1_byte(pcs, 0, 0) ^ data[i];
        if ((i & 7) == 0) par[i >> 3] = 0;
        par[i >> 3] |= (uint8_t)(((filter(pcs->odd) ^ oddparity8(bt)) & 1) << (7 - (i & 7)));
    }
}

/* Encrypt `len` bytes in place while feeding the cipher `feed` (one input byte per data byte, LSB-first) and
 * fill the MSB-first encrypted parity array. `feed`=NULL is the plain keystream (== mf_crypto1_encrypt); a
 * non-NULL feed (cuid^nonce) both encrypts and advances the cipher exactly like a first-auth crypto1_word,
 * which is what a Nested-auth encrypted nt needs. Port of the estream_next per-bit path. */
static inline void mf_crypto1_encrypt_feed(c1_t *pcs, uint8_t *data, int len, const uint8_t *feed, uint8_t *par)
{
    for (int i = 0; i < len; i++) {
        uint8_t bt = data[i], enc = 0;
        for (int j = 0; j < 8; j++) {
            uint8_t fb = feed ? ((feed[i] >> j) & 1) : 0;
            enc |= (uint8_t)((c1_bit(pcs, fb, 0) ^ ((bt >> j) & 1)) << j);
        }
        data[i] = enc;
        if ((i & 7) == 0) par[i >> 3] = 0;
        par[i >> 3] |= (uint8_t)(((filter(pcs->odd) ^ oddparity8(bt)) & 1) << (7 - (i & 7)));
    }
}

/* Decrypt `len` received cipher bytes in place (keystream = c1_byte(feed 0)). Port of mf_crypto1_decryptEx
 * (multi-byte path). */
static inline void mf_crypto1_decrypt(c1_t *pcs, uint8_t *data, int len)
{
    for (int i = 0; i < len; i++) data[i] = c1_byte(pcs, 0, 0) ^ data[i];
}

#endif /* FANTASI_RFID_ISO14A_EMU_H */
