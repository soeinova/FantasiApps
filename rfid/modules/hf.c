/* rfid feature module: HF (13.56 MHz) reader.
 *
 * Probes ISO14443-A and, on a hit, appends one display line to RFID_SCAN_FILE for
 * the driver to fold into its list. One of the modules the rfid driver (rfid.c)
 * hot-loads into RAM for a scan and unloads right after - so it's resident only
 * for the HF leg. Reads nothing from flash; drives the reader through the
 * loader-resolved fantasi_rfid() table. Returns the number of tags found. */
#include "app_api.h"
#include "app_rfid.h"
#include "scan.h"

int app_main(const fantasi_api_t *api)
{
    const fantasi_rfid_t *r = fantasi_rfid();
    if (!r || !(r->caps() & FANTASI_RFID_CAP_HF_READ)) return 0;
    if (r->set_mode(FANTASI_RFID_HF_READER) != 0) return 0;

    r->field(1);
    api->delay(10);                       /* field settle / card power-up */

    uint8_t uid[10], sak = 0, atqa[2] = {0, 0};
    int uid_len = 0, cascade = 0;
    int rc = r->iso14443a_select(uid, &uid_len, &sak, atqa, &cascade);

    r->field(0);
    r->set_mode(FANTASI_RFID_OFF);
    if (rc != 0 || uid_len <= 0) return 0;   /* no tag in range */

    char line[96];
    int n = scan_str(line, 0, "HF  ISO14443A  UID ");
    n = scan_hex(line, n, uid, uid_len);
    n = scan_str(line, n, "  SAK ");
    n = scan_byte(line, n, sak);
    line[n++] = '\n';
    api->write_file(RFID_SCAN_FILE, line, (uint32_t)n);
    return 1;
}
