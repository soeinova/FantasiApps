/* rfid feature module: MIFARE Classic 1K tag emulation (`emulate mfc`).
 *
 * Emulates a MIFARE Classic 1K card from a 1024-byte image (64 blocks x 16 B; sector trailers carry the
 * keys) staged at /ramfs/mfc_emu.bin by the host. The HAL does only the real-time bit I/O + FDT
 * (hf_emu_recv Miller-decodes the reader command; hf_emu_send load-modulates our reply at the frame delay
 * time); this module is the protocol: ISO14443-A anticollision (ATQA / UID+BCC / SAK), Crypto1
 * authentication as a tag (generate nt, verify nr/ar, answer at), and encrypted block reads served from the
 * image. Response encoding lives in iso14a_emu.h; Crypto1 in mfc_common.h. Port of armsrc/mifaresim.c
 * Mifare1ksim (first-auth path; write/nested-attack branches dropped for a static read clone).
 * Deleted after use. Stop by pressing a key on the host (read_input). */
#define MFC_FAST_FILTER                    /* byte-table Crypto1 filter (LUTs built at runtime) */
#include "iso14a_emu.h"

#define EMU_IMG   "/ramfs/mfc_emu.bin"     /* 1024-byte card image from the host */
#define FILT_TAB_SZ 512                    /* two 256-entry filter LUTs, generated into the heap alloc below */
#define EMU_BLOCKS 64

enum { E_IDLE = 0, E_SELECT, E_AUTH1, E_WORK };

/* 48-bit sector key from the image: sector trailer = sector*4+3; KeyA at byte 0, KeyB at byte 10. */
static uint64_t emu_key(const uint8_t *card, int sector, int keytype)
{
    const uint8_t *k = card + (sector * 4 + 3) * 16 + (keytype ? 10 : 0);
    uint64_t v = 0;
    for (int i = 0; i < 6; i++) v = v << 8 | k[i];
    return v;
}

/* big-endian 4-byte store */
static void put_be32(uint8_t *d, uint32_t v) { d[0] = v >> 24; d[1] = v >> 16; d[2] = v >> 8; d[3] = v; }

/* A valid weak-Crypto1-LFSR nonce: the low 16 bits are the 16-clock successor of the high 16 (exactly what
 * is_weak_prng_nonce checks). Real weak/static MIFARE Classic cards only ever return one of these, so pm3
 * finds its LFSR index; an arbitrary 32-bit value is not one and pm3 flags it (idx -1). Given the high half,
 * derive the matching low half. */
static uint32_t weak_nonce(uint16_t hi)
{
    uint16_t x = (uint16_t)((hi & 0xff) << 8 | hi >> 8);
    for (int i = 0; i < 16; i++)
        x = (uint16_t)(x >> 1 | ((x ^ x >> 2 ^ x >> 3 ^ x >> 5) & 1) << 15);
    uint16_t lo = (uint16_t)((x & 0xff) << 8 | x >> 8);
    return (uint32_t)hi << 16 | lo;
}

/* Streaming Crypto1 reply source for hf_emu_send_stream: yields one subcarrier symbol per call, encrypting
 * the plaintext bit-by-bit (keystream ^ data, LSB-first) with an encrypted parity symbol after each byte, so
 * the crypto hides in the paced feed and the reply's FDT stays low. Symbol order = start bit, then per byte
 * (8 data bits + 1 parity), then stop bit -> len*9 + 2 symbols. Mirrors mf_crypto1_encryptEx: `feed` (or 0)
 * is the cipher input byte-stream - 0 for a plain encrypted reply (at/read), cuid^nonce for the Nested nt
 * (which both encrypts nt and advances the cipher exactly like a first-auth's crypto1_word). `feed` field is
 * last so the plain-reply inits ({..., feed defaults to 0}) stay valid. */
typedef struct { c1_t *cs; const uint8_t *pt; int len, st, bi, ni; const uint8_t *feed; } estream_t;
static uint8_t estream_next(void *c)
{
    estream_t *s = (estream_t *)c;
    if (s->st == 0) { s->st = 1; return TAG_SEC_D; }                 /* start bit */
    if (s->st == 1) {
        if (s->bi < 8) {                                            /* one encrypted data bit (LSB-first) */
            uint8_t fb = s->feed ? ((s->feed[s->ni] >> s->bi) & 1) : 0;  /* feed 0 (at/read) or cuid^nonce (nested nt) */
            uint8_t bit = c1_bit(s->cs, fb, 0) ^ ((s->pt[s->ni] >> s->bi) & 1);
            s->bi++;
            return bit ? TAG_SEC_D : TAG_SEC_E;
        }
        uint8_t pbit = filter(s->cs->odd) ^ oddparity8(s->pt[s->ni]);   /* encrypted parity (no cipher advance) */
        s->bi = 0; s->ni++;
        if (s->ni >= s->len) s->st = 2;
        return pbit ? TAG_SEC_D : TAG_SEC_E;
    }
    s->st = 3; return TAG_SEC_F;                                     /* stop bit */
}

/* Send a Crypto1 tag reply, letting each frontend use its best path from this one module:
 *  - Streaming frontends (PM3 FPGA feed, Chameleon NFCT DMA) overlap the per-symbol producer with transmission
 *    for a low FDT - hf_emu_send_stream returns >=0 and we're done, cipher advanced by estream_next.
 *  - A frontend that can't overlap (CPU-bit-banged TX, e.g. Flipper - computing mid-symbol smears the subcarrier)
 *    returns <0 (no strong hf_emu_send_stream); then we pre-encode the whole reply with the tight in-place loop
 *    (far faster than draining 164 per-symbol callbacks) and hand the buffer to hf_emu_send_stream_buf.
 * `pt` is writable scratch (encrypted in place on the buffer path); `feed`=NULL for a plain reply (at/read) or
 * cuid^nonce for the nested nt. The buffer path + its ts[] compile only under EMU_STREAM_BUF (the cm4 build that
 * a bit-banged frontend needs), so the RAM-tight PM3 (arm7) carries the streaming path alone. */
static void send_crypto(const fantasi_rfid_t *r, c1_t *cs, uint8_t *pt, int len, const uint8_t *feed, uint8_t *ts)
{
    estream_t es = { cs, pt, len, 0, 0, 0, feed };
    if (r->hf_emu_send_stream(estream_next, &es, len * 9 + 2) >= 0) return;   /* streamed with overlap */
#ifdef EMU_STREAM_BUF
    uint8_t par[(18 + 7) / 8];                                                /* MSB-first encrypted parity */
    if (feed) mf_crypto1_encrypt_feed(cs, pt, len, feed, par);
    else      mf_crypto1_encrypt(cs, pt, len, par);
    r->hf_emu_send_stream_buf(ts, iso14a_tag_encode(pt, len, par, ts));
#else
    (void)ts;                                                                /* no buffer-send frontend here */
#endif
}

int app_main(const fantasi_api_t *api)
{
    const fantasi_rfid_t *r = fantasi_rfid();
    if (!r || !r->hf_emu_recv || !r->hf_emu_send || !(r->caps() & FANTASI_RFID_CAP_HF_EMU)) {
        api->print("mfc_emu: emulation not supported on this device\r\n"); return 0;
    }

    /* set_mode first, before any module malloc: it decompresses the HF FPGA bitstream and needs a large
     * contiguous heap block; a prior card/table malloc fragments the heap and OOMs that load. */
    if (r->set_mode(FANTASI_RFID_HF_EMU) != 0) { api->print("mfc_emu: HF emulation unavailable\r\n"); return 0; }

    /* Card image on the heap, not in .bss: the loader lays .bss into the load-time image block, so a 1 KB
     * static here would bloat that block and, together with the inlined-Crypto1 .text, push the module over
     * the ramfs load budget. Allocating it at runtime (after set_mode + the load's transient symtab/strtab are
     * freed) keeps the load small; we also drop the ramfs image copy once it's in RAM. The +512 holds the
     * runtime-built byte-table filter LUTs. */
    uint8_t *card = api->malloc(EMU_BLOCKS * 16 + FILT_TAB_SZ);   /* card image + the 512 B filter LUTs */
    if (!card) { api->print("mfc_emu: out of memory\r\n"); r->set_mode(FANTASI_RFID_OFF); return 0; }
    mfc_filter_init(card + EMU_BLOCKS * 16);                       /* build the byte-table filter LUTs */
    if (api->read_file(EMU_IMG, (char *)card, EMU_BLOCKS * 16) < (int)(EMU_BLOCKS * 16)) {
        api->print("mfc_emu: no card image\r\n"); api->free(card); r->set_mode(FANTASI_RFID_OFF); return 0;
    }
    api->remove(EMU_IMG);                                 /* image is in RAM now - free the ramfs copy */

    /* Identity from block 0: UID = bytes 0-3, then the standard 1K ATQA/SAK (block 0's own SAK/ATQA bytes
     * are the card's manufacturer copy; anticollision uses the fixed 1K values). */
    uint8_t uid[4]; for (int i = 0; i < 4; i++) uid[i] = card[i];
    uint8_t bcc = uid[0] ^ uid[1] ^ uid[2] ^ uid[3];
    uint8_t atqa[2] = { 0x04, 0x00 };
    uint8_t sak = 0x08;
    uint32_t cuid = be32(uid);
    api->printf("mfc_emu: emulating MIFARE Classic 1K uid=%02X%02X%02X%02X - press a key to stop\r\n",
                uid[0], uid[1], uid[2], uid[3]);

    /* Pre-encode the static anticollision replies once (like stock MifareSimInit): the FDT-critical hot path
     * then just streams the precompiled ToSend buffer - no per-reply parity+Manchester encode - so the reply
     * reliably lands inside the FPGA's ~48 us fdt_indicator window.
     *
     * Tag nonce: a fixed valid weak-LFSR nonce derived from the UID and pre-encoded so the first-auth nt lands
     * in the FDT window (82 us). Real weak/static MIFARE Classic cards return exactly such a nonce, so pm3
     * finds its LFSR index; an arbitrary value like 0x0A0B0C0D is not weak-valid and pm3 flags it (idx -1). */
    uint32_t nonce = weak_nonce((uint16_t)(cuid ^ (cuid >> 16)));

    uint8_t ts_atqa[24], ts_uid[52], ts_sak[36], ts_nt[48];
    int n_atqa, n_uid, n_sak, n_nt;
    {
        uint8_t pp;
        iso14a_parity(atqa, 2, &pp); n_atqa = iso14a_tag_encode(atqa, 2, &pp, ts_atqa);
        uint8_t u[5] = { uid[0], uid[1], uid[2], uid[3], bcc };
        iso14a_parity(u, 5, &pp); n_uid = iso14a_tag_encode(u, 5, &pp, ts_uid);
        uint8_t sk[3]; sk[0] = sak; crc_a(sk, 1, sk + 1);
        iso14a_parity(sk, 3, &pp); n_sak = iso14a_tag_encode(sk, 3, &pp, ts_sak);
        uint8_t ntb[4]; put_be32(ntb, nonce);                /* weak card: pre-encode the static nt */
        iso14a_parity(ntb, 4, &pp); n_nt = iso14a_tag_encode(ntb, 4, &pp, ts_nt);
    }

    uint8_t rx[64], rxpar[16], resp[24];
    c1_t cs;
    int state = E_IDLE, authed = 0, authsc = 0, authkey = 0;
    uint32_t suc64 = prng_successor(nonce, 64);   /* expected reader answer ar (constant - fixed nonce) */
    uint32_t at_pt = prng_successor(nonce, 96);   /* at plaintext (constant) - keeps AUTH1 out of prng loops */
#ifdef EMU_STREAM_BUF
    uint8_t ts[3 + 9 * 18];   /* pre-encode scratch for the buffer-send fallback (bit-banged frontends); holds
                               * up to the 18-byte READ. Compiled only where a non-streaming frontend needs it. */
#else
    uint8_t *ts = 0;          /* streaming-only build: send_crypto never touches it */
#endif

    for (;;) {
        int n = r->hf_emu_recv(rx, rxpar, sizeof rx, 100);
        if (n <= 0) {                                     /* idle: poll the host stop key only now, keeping the
                                                           * real-time recv->send path clear of the slow syscall */
            uint8_t kb;
            if (api->read_input(&kb, 1) > 0) break;
            continue;
        }

        /* REQA / WUPA (7-bit short frame) -> ATQA (send first, then bookkeeping), fresh nonce */
        if (n == 1 && (rx[0] == 0x26 || rx[0] == 0x52)) {
            r->hf_emu_send(ts_atqa, n_atqa);
            state = E_SELECT; authed = 0;
            continue;
        }

        if (state == E_SELECT || state == E_WORK) {
            if (n >= 2 && rx[0] == 0x93 && rx[1] == 0x20) {            /* ANTICOLL CL1 -> UID + BCC */
                r->hf_emu_send(ts_uid, n_uid);
                continue;
            }
            if (n >= 2 && rx[0] == 0x93 && rx[1] == 0x70) {            /* SELECT CL1 -> SAK + CRC */
                r->hf_emu_send(ts_sak, n_sak);
                state = E_WORK; authed = 0;
                continue;
            }
        }

        if (state == E_WORK) {
            uint8_t cmd[64];
            /* Post-auth reader commands (READ/AUTH/HALT/...) are always 4 bytes (2 data + 2 CRC), fully encrypted,
             * and the reader clocks its cipher over all 4. A frontend whose edge decoder drops a trailing sequence-Y
             * (no-pause) CRC byte returns n=3 - and since the encrypted CRC varies with the reader's random nr, this
             * is intermittent. Decrypting only n bytes then advances our cipher too little -> the reply keystream
             * desyncs -> garbage. Crypto1's post-auth advance is data-independent (c1_byte feed 0), so pad the lost
             * byte(s) with 0 and decrypt the full 4: only the 32-bit count must match the reader, not the values.
             * No-op on hardware-framed frontends (PM3/Chameleon) that already return the full 4. */
            if (authed && n >= 1 && n < 4) { for (int i = n; i < 4; i++) rx[i] = 0; n = 4; }
            for (int i = 0; i < n; i++) cmd[i] = rx[i];
            if (authed) mf_crypto1_decrypt(&cs, cmd, n);              /* post-auth frames are encrypted */

            if (n >= 2 && (cmd[0] == 0x60 || cmd[0] == 0x61)) {        /* AUTH key A/B for a block */
                int nested = authed;                                  /* 60/61 while already authenticated = nested */
                authkey = cmd[0] - 0x60;
                authsc  = cmd[1] >> 2;                                 /* block -> sector (4 blocks/sector) */
                uint8_t ntb[4], ksb[4];
                put_be32(ntb, nonce); put_be32(ksb, cuid ^ nonce);
                c1_init(&cs, emu_key(card, authsc, authkey));
                if (!nested) {
                    r->hf_emu_send(ts_nt, n_nt);                     /* first auth: static nt pre-encoded (82us FDT) */
                    c1_word(&cs, cuid ^ nonce, 0);                    /* advance cipher (feeds cuid^nonce) */
                } else {
                    /* Nested auth: nt is encrypted. Stream it feeding cuid^nonce, which both encrypts nt and
                     * advances the cipher to the same state a first auth reaches - so AUTH1 below is unchanged.
                     * Streamed => low FDT even though it's a crypto reply. Mirrors mf_crypto1_encryptEx. */
                    send_crypto(r, &cs, ntb, 4, ksb, ts);            /* nested nt: feed cuid^nonce */
                }
                state = E_AUTH1;
                continue;
            }

            if (n >= 2 && cmd[0] == 0x30 && authed) {                  /* READ block */
                int blk = cmd[1];
                if (blk < 0 || blk >= EMU_BLOCKS) continue;
                for (int i = 0; i < 16; i++) resp[i] = card[blk * 16 + i];
                /* Access control: apply the sector-trailer read rules a real card enforces. KeyA is never
                 * readable; KeyB is readable (by a KeyA auth) only in access configs 000/010/001; the access
                 * bytes + GPB are always readable. Access bits (C1/C2/C3 for the trailer = block 3): C1 from
                 * trailer byte7 bit7, C2 from byte8 bit3, C3 from byte8 bit7. */
                if ((blk & 3) == 3) {
                    int c1 = (resp[7] >> 7) & 1, c2 = (resp[8] >> 3) & 1, c3 = (resp[8] >> 7) & 1;
                    int keyb_readable = (c1 == 0) && !(c2 && c3);
                    for (int i = 0; i < 6; i++) resp[i] = 0;               /* KeyA */
                    if (!keyb_readable) for (int i = 10; i < 16; i++) resp[i] = 0;  /* KeyB */
                }
                crc_a(resp, 16, resp + 16);
                send_crypto(r, &cs, resp, 18, 0, ts);                /* encrypted READ reply (16 data + 2 CRC) */
                continue;
            }

            if (n >= 2 && cmd[0] == 0x50) { state = E_IDLE; authed = 0; continue; }  /* HALT */
        }

        /* nr||ar is always 8 bytes. If a frontend's edge decoder loses a trailing sequence-Y (0x00, no-pause)
         * byte it returns n=7; pad the missing byte(s) with 0 (they're 0 by definition) so the crypto sees the
         * full nr||ar. No-op on hardware-framed frontends (PM3/Chameleon) that already return all 8. */
        if (state == E_AUTH1 && n >= 4 && n <= 8) {                   /* reader answer nr || ar */
            for (int i = n; i < 8; i++) rx[i] = 0;                    /* trailing all-Y bytes the decoder lost */
            uint32_t nr = be32(rx), ar = be32(rx + 4);
            c1_word(&cs, nr, 1);
            uint32_t cardRr = ar ^ c1_word(&cs, 0, 0);
            if (cardRr != suc64) { state = E_WORK; authed = 0; continue; }   /* auth KO: real tags stay silent */
            put_be32(resp, at_pt);                                    /* at (precomputed plaintext) */
            send_crypto(r, &cs, resp, 4, 0, ts);                     /* third-pass at */
            state = E_WORK; authed = 1;
            continue;
        }
    }

    r->set_mode(FANTASI_RFID_OFF);
    api->free(card);
    api->print("mfc_emu: stopped\r\n");
    return 1;
}
