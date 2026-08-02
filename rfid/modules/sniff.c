/* rfid feature module: passive HF ISO14443-A sniffer.
 *
 * One of the modules the rfid driver (rfid.c) hot-loads into RAM - resident only
 * while `sniff hf` runs, then deleted. Continuously captures a live 13.56 MHz
 * reader<->card exchange through the loader-resolved fantasi_rfid() table and
 * streams the decoded trace to the driver's session console; any key (or Ctrl-C)
 * stops it. Unlike `raw` there is no request/result file - the decode lives in
 * firmware (hf_sniff_capture / hf_sniff), so this module is just the loop that
 * drives it and prints. It owns its capture scratch: one heap block for the
 * duration, freed on exit, so nothing lingers to fragment the tiny PM3 heap. */
#include "app_api.h"
#include "app_rfid.h"

int app_main(const fantasi_api_t *api)
{
    const fantasi_rfid_t *r = fantasi_rfid();
    if (!r || (!r->hf_sniff_capture && !r->hf_sniff)) return 0;

    /* set_mode is a cached no-op here - the driver pre-warms the HF bitstream before
     * loading this module so the module image and the 4 KB FPGA-config window never
     * occupy the heap together (same reasoning as the raw module). */
    if (r->set_mode(FANTASI_RFID_HF_READER) != 0) { api->print("sniff: HF frontend unavailable\r\n"); return 0; }

    /* Ephemeral capture scratch: the HAL carves its DMA ring + decode buffers + output
     * text out of this and leaves the decoded trace at buf[0..n]. Freed on exit. */
    char *buf = api->malloc(FANTASI_RFID_SNIFF_BUFSZ);
    if (!buf) { r->set_mode(FANTASI_RFID_OFF); api->print("sniff: out of memory\r\n"); return 0; }

    api->print("sniffing - press any key to stop\r\n");
    char key[8];
    /* Flush any input already queued (notably the '\n' that terminated the "sniff hf" command
     * line): it can land in the app-input stream a beat later and abort the capture early. */
    while (api->read_input(key, sizeof key) > 0) { }

    /* hf_sniff_capture is the file-less caller-buffer primitive (preferred); hf_sniff is the
     * older /ramfs file path (Flipper/Chameleon). Each pass passively measures the external
     * field and sets the front-end gain to match before capturing, so a hand-held reader stays
     * correctly gained as the distance drifts. */
    int use_capture = (r->hf_sniff_capture != 0);
    for (;;) {
        int n = 0;
        if (use_capture) {
            n = r->hf_sniff_capture((uint8_t *)buf, FANTASI_RFID_SNIFF_BUFSZ, 250, 2500);
            if (n < 0) { use_capture = 0; n = 0; }   /* this frontend sniffs via the file path instead */
        } else if (r->hf_sniff) {
            if (r->hf_sniff("/ramfs/sniff.txt", 250) > 0)
                n = api->read_file("/ramfs/sniff.txt", buf, FANTASI_RFID_SNIFF_BUFSZ - 1);
        }
        if (n > 0) {
            /* Print the decoded trace - the L<..> header and "<R|C> <start> <end> <hex>[!].." frame
             * lines - line by line with CRLF. The host CLI tabulates them (CRC, protocol names,
             * colour); the wire stays plain text so a raw serial terminal still shows a readable trace. */
            buf[n] = '\0';
            for (int i = 0; i < n; ) {
                int j = i;
                while (j < n && buf[j] != '\n') j++;
                if (j > i) { buf[j] = '\0'; api->printf("%s\r\n", buf + i); }
                i = j + 1;
            }
        }
        if (api->read_input(key, sizeof key) > 0) break;   /* any key stops the loop */
    }

    api->free(buf);
    r->set_mode(FANTASI_RFID_OFF);                 /* sniff is passive; always release the frontend */
    if (!use_capture) api->remove("/ramfs/sniff.txt");
    api->print("sniff stopped\r\n");
    return 1;
}
