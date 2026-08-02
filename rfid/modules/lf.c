/* rfid feature module: LF (125 kHz) reader.
 *
 * Probes EM4100 and, on a hit, appends one display line to RFID_SCAN_FILE. One of
 * the modules the rfid driver (rfid.c) hot-loads for the LF leg of a scan and
 * unloads right after. The lf_em4100() call is self-contained (powers the field,
 * captures, decodes, powers down). Returns the number of tags found. */
#include "app_api.h"
#include "app_rfid.h"
#include "scan.h"

int app_main(const fantasi_api_t *api)
{
    const fantasi_rfid_t *r = fantasi_rfid();
    if (!r || !r->lf_em4100) return 0;
    if (!(r->caps() & FANTASI_RFID_CAP_LF_READ)) return 0;

    uint8_t uid[5];
    int rate = r->lf_em4100(uid);
    if (rate < 0) return 0;               /* no tag / read error */

    char line[64];
    int n = scan_str(line, 0, "LF  EM4100     ID ");
    n = scan_hex(line, n, uid, 5);
    n = scan_str(line, n, "  (RF/");
    n = scan_dec(line, n, (uint32_t)rate);
    n = scan_str(line, n, ")");
    line[n++] = '\n';
    api->write_file(RFID_SCAN_FILE, line, (uint32_t)n);
    return 1;
}
