/* Shared contract between the rfid driver (rfid.c) and its feature modules
 * (hf.c, lf.c) - all built from this one app folder into separate loadable ELFs.
 *
 * A module probes one protocol and, for each tag in range, appends a display
 * line to RFID_SCAN_FILE. The driver clears that file before running a module,
 * then reads it back and folds the lines into one numbered list. Keeping the
 * per-protocol formatting in the modules (not the driver) is what lets the driver
 * stay thin. Apps link -nostdlib, so the little string builders live here as
 * static inlines rather than in a shared .c (which couldn't be its own ELF). */
#ifndef RFID_SCAN_H
#define RFID_SCAN_H

#include <stdint.h>

#define RFID_SCAN_FILE "/ramfs/.rfidfound"

/* Append `s` to b[] at offset n; return the new length. */
static inline int scan_str(char *b, int n, const char *s) { while (*s) b[n++] = *s++; return n; }

/* Append `len` bytes as space-separated hex; return the new length. */
static inline int scan_hex(char *b, int n, const uint8_t *p, int len)
{
    static const char H[] = "0123456789ABCDEF";
    for (int i = 0; i < len; i++) { if (i) b[n++] = ' '; b[n++] = H[p[i] >> 4]; b[n++] = H[p[i] & 0xF]; }
    return n;
}

/* Append one byte as two hex digits; return the new length. */
static inline int scan_byte(char *b, int n, uint8_t v)
{
    static const char H[] = "0123456789ABCDEF";
    b[n++] = H[v >> 4]; b[n++] = H[v & 0xF]; return n;
}

/* Append an unsigned value in decimal; return the new length. */
static inline int scan_dec(char *b, int n, uint32_t v)
{
    char t[10]; int k = 0;
    do { t[k++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (k) b[n++] = t[--k];
    return n;
}

#endif /* RFID_SCAN_H */
