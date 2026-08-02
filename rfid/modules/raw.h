/* Shared contract for the rfid driver's `raw` interface (rfid.c) and its raw
 * module (raw.c) - one loadable ELF built from this app folder, like hf/lf.
 *
 * The point of this header is raw_txrx(): the single send/receive path every raw
 * exchange goes through, so trace logging is written once and picked up by every
 * command that transceives (raw now; select, follow-ups, future protocol steps
 * later). Each logged frame is one plain-text line "<R|C> <hex>" appended to a
 * caller-supplied buffer - the host CLI tabulates it (CRC + protocol names), so
 * the wire stays cheap text (a raw serial terminal still shows a readable trace),
 * matching the sniff split. Apps link -nostdlib, so these are static inlines. */
#ifndef RFID_RAW_H
#define RFID_RAW_H

#include <stdint.h>
#include "app_rfid.h"
#include "scan.h"                 /* scan_hex - shared hex writer */

/* raw request, driver -> module via a file: byte 0 = flags, byte 1 = frame length, then the frame. */
#define RAW_REQ    "/ramfs/.rawreq"
#define RAW_LAST   "/ramfs/.rawlast"    /* module -> driver: the just-exchanged frames, one per line */
#define RAW_F_CRC     (1u << 0)   /* append CRC_A to the transmitted frame (like pm3 `-c`) */
#define RAW_F_KEEP    (1u << 1)   /* leave the field ON afterwards, for follow-up commands (`-k`) */
#define RAW_F_SELECT  (1u << 2)   /* select the card (anticollision + select) first (`-s`) */

/* ISO14443-A CRC_A (poly 0x8408, init 0x6363) - the reader appends it in software
 * (the ST25R3916 transceive never HW-appends TX CRC; see hal_rfid_hf_transceive). */
static inline uint16_t raw_crc(const uint8_t *d, int n)
{
    uint32_t crc = 0x6363;
    for (int i = 0; i < n; i++) {
        uint8_t b = (uint8_t)(d[i] ^ (crc & 0xFF));
        b = (uint8_t)(b ^ (b << 4));
        crc = (crc >> 8) ^ ((uint32_t)b << 8) ^ ((uint32_t)b << 3) ^ ((uint32_t)b >> 4);
    }
    return (uint16_t)crc;
}

/* A growable text trace: each frame becomes one "<R|C> <hex>\n" line. */
typedef struct { char *buf; int len, cap; } rawtrace_t;

static inline void raw_log(rawtrace_t *t, char dir, const uint8_t *b, int n)
{
    if (n < 0) n = 0;
    if (t->len + n * 3 + 4 >= t->cap) return;      /* bounded: drop rather than overflow */
    t->buf[t->len++] = dir; t->buf[t->len++] = ' ';
    t->len = scan_hex(t->buf, t->len, b, n);
    t->buf[t->len++] = '\n';
}

/* The single send/receive path: log the TX frame ('R'), transceive, log the RX frame ('C').
 * tx_bits allows short frames (7-bit WUPA/REQA) and anticollision. Returns hf_transceive's result
 * (received bit count, or <0 - see hal_rfid.h RFID_ERR_*). RX carries its CRC bytes (CRC_RX unset),
 * so the host can check them. */
static inline int raw_txrx(rawtrace_t *t, const fantasi_rfid_t *r,
                           const uint8_t *tx, int tx_bits, uint32_t flags,
                           uint8_t *rx, int rx_cap)
{
    raw_log(t, 'R', tx, (tx_bits + 7) / 8);
    int rb = r->hf_transceive(tx, tx_bits, flags, rx, rx_cap, 0);
    if (rb > 0) raw_log(t, 'C', rx, (rb + 7) / 8);
    return rb;
}

#endif /* RFID_RAW_H */
