/* rfid - the RFID app: an interactive sub-CLI.
 *
 * Launched resident, it presents its own `rfid>` prompt and dispatches commands
 * typed at the launching console:
 *
 *   search        scan every band in series, list the tags in range
 *   exit / quit   leave the app   (Ctrl-C leaves too - the launcher aborts it)
 *
 * `help` is rendered host-side (cli/commands/rfid.c, like the main CLI's help) and
 * never reaches the device, so this app carries no help text - it just dispatches
 * the real verbs below and leaves unknown lines to the "unknown command" fallback.
 *
 * More verbs (clone, write, ...) slot into dispatch(). The app owns no protocol
 * code: `search` hot-loads a feature module (hf, lf, ... - built from this same
 * app folder into separate ELFs) per band via fantasi_run_module(), runs it, and
 * lets the firmware unload it, so only one module is resident at a time and none
 * live in flash. Each module writes the tags it finds to RFID_SCAN_FILE; the
 * driver folds those into one numbered list.
 *
 * Input arrives through api->read_input (the launcher forwards the user's
 * keystrokes raw, with no echo), so the app echoes what you type and emits CRLF
 * itself. On a screen device this same driver would paint a menu instead. */
#include "app_api.h"
#include "app_rfid.h"
#include "scan.h"
#include "raw.h"

#define PROMPT      "rfid> "
#define LINE_MAX    64
/* s_trace (raw-command replay log) size. Kept small on the Proxmark3 (ARM7), whose WebUSB heap is tight
 * once the loaded app image is resident. The sniff capture scratch (FANTASI_RFID_SNIFF_BUFSZ) is not
 * here at all - it lives in the hot-loaded sniff module, allocated only while sniffing and freed after. */
#if defined(__ARM_ARCH_4T__)
#define RFID_BUF_SZ 512
#else
#define RFID_BUF_SZ 4096
#endif
#define FETCH_LIMIT 100    /* ~5 s for a requested module to arrive */
#define POLL_MS     50
#define RFID_FPGA_RDY "/ramfs/fpga.rdy"   /* host writes this (ramfs) once a bitstream
                                           * finishes committing to /fpga (lfs); must
                                           * match cli/commands/rfid.c */

static int streq(const char *a, const char *b) { while (*a && *b) { if (*a++ != *b++) return 0; } return *a == *b; }

/* If *pp begins with the whole word `w` (followed by a space or end), advance *pp past it
 * (and any trailing spaces) and return 1; else leave *pp and return 0. Used to peel an
 * optional leading <target> token off a command's argument string. */
static int pop_word(const char **pp, const char *w)
{
    const char *s = *pp;
    while (*w) { if (*s++ != *w++) return 0; }
    if (*s != ' ' && *s != '\0') return 0;
    while (*s == ' ') s++;
    *pp = s;
    return 1;
}

static int s_field;    /* the driver's view of the reader carrier (1 = on); `field status` reports it, and
                        * the field-changing commands (field/raw/search/sniff) keep it current */

/* Bands to scan, in order. key names the module the host streams; path is the
 * /ramfs slot it lands in (host convention: /ramfs/rfid_<key>); mode is the RFID
 * mode whose FPGA bitstream (if any) must be provisioned before the module runs. */
static const struct { const char *key, *label, *path; int mode; } BANDS[] = {
    { "hf", "HF", "/ramfs/rfid_hf", FANTASI_RFID_HF_READER },
    { "lf", "LF", "/ramfs/rfid_lf", FANTASI_RFID_LF_READER },
};
#define NBANDS ((int)(sizeof BANDS / sizeof BANDS[0]))

/* dst = a + b + c, truncated to cap (no libc strcat/snprintf in module land). */
static void join3(char *dst, int cap, const char *a, const char *b, const char *c)
{
    const char *parts[3] = { a, b, c };
    int i = 0;
    for (int p = 0; p < 3; p++)
        for (const char *s = parts[p]; *s && i < cap - 1; ) dst[i++] = *s++;
    dst[i] = '\0';
}

/* Obtain band b's module just in time: use it if it's already in /ramfs, else ask
 * the host to stream it over the session's protobuf channel and wait for it to
 * land. Returns 1 if the module is now resident, 0 if it never arrived (no host /
 * host lacks it). Nothing is pre-staged; the caller deletes it after use. */
/* Wait for a requested module file to be fully delivered: poll until its size appears and stops growing.
 * A chunked host upload otherwise races the poll - returning at the first size >= 0 would hand app_load a
 * partial ELF (its section headers sit past the truncated end). Two consecutive
 * equal, non-negative sizes means the upload has settled. */
// TODO: Mutex or other lock to reduce polling time and eliminate race conditions here - noproto
static int obtain_wait(const fantasi_api_t *api, const char *path)
{
    int prev = -2;
    for (int waited = 0; ; ) {
        int sz = (int)api->file_size(path);
        if (sz >= 0 && sz == prev) return 1;            /* delivered + stable */
        prev = sz;
        if (++waited > FETCH_LIMIT) return sz >= 0 ? 1 : 0;
        api->delay(POLL_MS);
    }
}

static int obtain_module(const fantasi_api_t *api, int b)
{
    if (api->file_size(BANDS[b].path) >= 0) return 1;   /* already here */
    api->request_module(BANDS[b].key);                  /* JIT request to the host */
    return obtain_wait(api, BANDS[b].path);
}

/* Ensure band b's FPGA bitstream is cached under /fpga (Proxmark3 only). If the
 * device needs one and it isn't there, ask the host to stream it in - same JIT
 * model as obtain_module, but written to persistent LittleFS so subsequent scans
 * load it straight from flash (no host, no re-transfer). Returns 1 when ready (or
 * none is needed - chip-based platforms), 0 if it never arrived. */
static int obtain_fpga(const fantasi_api_t *api, int b)
{
    const fantasi_rfid_t *r = fantasi_rfid();
    if (!r->fpga_resource) return 1;                    /* device without loadable gateware */
    const char *res = r->fpga_resource(BANDS[b].mode);
    if (!res) return 1;                                 /* no FPGA -> nothing to provision */

    char path[48], name[48];
    join3(path, sizeof path, "/fpga/", res, ".bit.z");
    if (api->file_size(path) >= 0) return 1;            /* already cached */

    api->mkdir("/fpga");
    api->remove(RFID_FPGA_RDY);                         /* clear any stale marker */
    join3(name, sizeof name, "fpga/", res, "");         /* host maps "fpga/<res>" -> the .z */
    api->request_module(name);

    /* Poll a ramfs ready marker, not the lfs bitstream. The host writes the marker
     * only after the ~28 KB .z is fully committed to LittleFS, so (a) we never treat
     * a half-uploaded file as done, and (b) we never open the lfs file while the
     * file-write task is committing it - the two tasks share one lfs_t with no lock,
     * so a concurrent open would clobber its shared caches. Modules are polled in
     * ramfs for exactly this reason; the bitstream just persists in lfs instead. */
    for (int waited = 0; api->file_size(RFID_FPGA_RDY) < 0; ) {
        if (++waited > FETCH_LIMIT) return 0;
        api->delay(POLL_MS);
    }
    api->remove(RFID_FPGA_RDY);
    return 1;
}

/* Print the lines a module just wrote to the scan file, each prefixed with a
 * running index; return how many tags were listed. */
static int list_found(const fantasi_api_t *api, int start)
{
    char buf[1024];
    int n = api->read_file(RFID_SCAN_FILE, buf, sizeof buf - 1);
    if (n <= 0) return 0;
    buf[n] = '\0';

    int count = 0, i = 0;
    while (buf[i]) {
        int j = i;
        while (buf[j] && buf[j] != '\n') j++;
        int nl = (buf[j] == '\n');               /* note terminator before we overwrite it */
        if (j > i) { buf[j] = '\0'; api->printf("  [%d] %s\r\n", start + count + 1, buf + i); count++; }
        if (!nl) break;
        i = j + 1;
    }
    return count;
}

/* `search`: scan every band in series. For each, stream the module in just in
 * time, hot-load it, run it, then delete it - so only one module is ever resident
 * and nothing persists. If a module can't be obtained the host isn't serving
 * them, so report disconnected and stop. */
static void scan(const fantasi_api_t *api, const char *args)
{
    while (*args == ' ') args++;
    /* optional <target>: restrict to one band; bare = every band. BANDS[0]=HF, [1]=LF. */
    int only = -1;
    if (*args) {
        if (streq(args, "nfca") || streq(args, "hf")) only = 0;
        else if (streq(args, "lf")) only = 1;
        else { api->printf("search: unknown target '%s' (try: nfca, lf)\r\n", args); return; }
    }
    api->print("scanning...\r\n");
    int total = 0;
    for (int b = 0; b < NBANDS; b++) {
        if (only >= 0 && b != only) continue;
        if (!obtain_module(api, b)) { api->print("disconnected: rfid modules unavailable\r\n"); return; }
        if (!obtain_fpga(api, b))   { api->print("disconnected: fpga bitstream unavailable\r\n"); return; }
        api->remove(RFID_SCAN_FILE);
        fantasi_run_module(BANDS[b].path, api, true);   /* frees the module file; writes RFID_SCAN_FILE */
        total += list_found(api, total);
        api->remove(BANDS[b].path);               /* no-op unless the load failed: run_module frees it */
    }
    api->remove(RFID_SCAN_FILE);
    s_field = 0;                                  /* each band module powers its field down after use */
    if (total == 0) api->print("no tags in range\r\n");
    else            api->printf("%d tag%s in range\r\n", total, total == 1 ? "" : "s");
}

#define SNIFF_MOD_KEY  "sniff"
#define SNIFF_MOD_PATH "/ramfs/rfid_sniff"

/* Stream in the sniff module JIT for one `sniff hf` run (deleted again after use, so it never
 * lingers as a heap island); a no-op re-fetch when it is somehow still present. */
static int obtain_sniff(const fantasi_api_t *api)
{
    if (api->file_size(SNIFF_MOD_PATH) >= 0) return 1;
    api->request_module(SNIFF_MOD_KEY);
    return obtain_wait(api, SNIFF_MOD_PATH);
}

/* `sniff hf`: passively capture a live 13.56 MHz reader<->card exchange. Hot-loads the HF sniff
 * module (which owns the capture loop + its scratch and streams the decoded trace), then deletes
 * it. Trigger a reader while it runs; any key (or Ctrl-C) stops it. The band arg keeps room for a
 * future `sniff lf`; bare `sniff` defaults to hf since it's the only one today. */
static void do_sniff(const fantasi_api_t *api, const char *args)
{
    /* <target>: the RF category to sniff. Only NFC-A (HF) has a sniffer on this build;
     * bare / "nfca" / "hf" all select it. Protocol targets (mfc, ul, ...) resolve to a
     * category host-side, so the device only ever sees the category token. */
    if (args[0] && !streq(args, "nfca") && !streq(args, "hf")) {
        api->printf("sniff: '%s' not supported (try: nfca)\r\n", args); return;
    }

    const fantasi_rfid_t *r = fantasi_rfid();
    if (!r || (!r->hf_sniff_capture && !r->hf_sniff)) {
        api->print("sniff: not supported on this device\r\n"); return;
    }
    /* Warm the HF bitstream first, before obtain_sniff puts the module file in ramfs, so fpga_load's
     * transient 4 KB config window allocates against the freest heap (same ordering fix as do_raw -
     * with the module file resident the window can't find 4 KB contiguous on the tight PM3 heap). */
    if (r->set_mode(FANTASI_RFID_HF_READER) != 0) { api->print("sniff: HF frontend unavailable\r\n"); return; }

    if (!obtain_sniff(api)) { api->print("disconnected: sniff module unavailable\r\n"); return; }

    fantasi_run_module(SNIFF_MOD_PATH, api, true);   /* true: free the file - sniff needs the heap */

    /* The module releases the frontend itself, but force off here too so an early module exit (e.g.
     * OOM) can't leave the reader mode latched. The module file is normally already gone (run_module
     * frees it as soon as the image is resident); this remove only catches the load-failed path. */
    r->set_mode(FANTASI_RFID_OFF);
    s_field = 0;
    api->remove(SNIFF_MOD_PATH);
}

/* ---- raw ISO14443-A frame TX/RX + a common trace log --------------------- */
#define RAW_MOD_KEY  "raw"
#define RAW_MOD_PATH "/ramfs/rfid_raw"
#define RAW_TRACE_BUF 1200   /* transient scratch to read back one command's trace (a full
                              * select+read is ~600 B); malloc'd per-command, never resident */

/* The trace log buffer, common across raw commands (the driver is resident, so it
 * persists where a per-invocation module's memory can't). Each `raw` exchange the
 * module logs to RAW_LAST is both shown and appended here; `trace` replays it. */
static char s_trace[RFID_BUF_SZ];
static int  s_tracelen;

/* If `line` is `cmd` optionally followed by args, return the args (past the spaces); else NULL. */
static const char *cmd_args(const char *line, const char *cmd)
{
    while (*cmd) if (*line++ != *cmd++) return 0;
    if (*line == '\0') return line;
    if (*line != ' ')  return 0;
    while (*line == ' ') line++;
    return line;
}

static int hexval(char c)
{ return (c>='0'&&c<='9')?c-'0':(c>='a'&&c<='f')?c-'a'+10:(c>='A'&&c<='F')?c-'A'+10:-1; }

/* Stream in the raw module JIT for one command (do_raw deletes it again after use, so
 * it never lingers as a heap island); a no-op re-fetch when it is somehow still present. */
static int obtain_raw(const fantasi_api_t *api)
{
    if (api->file_size(RAW_MOD_PATH) >= 0) return 1;
    api->request_module(RAW_MOD_KEY);
    for (int waited = 0; api->file_size(RAW_MOD_PATH) < 0; ) {
        if (++waited > FETCH_LIMIT) return 0;
        api->delay(POLL_MS);
    }
    return 1;
}

/* ---- LF T5577 raw write (its own hot-loaded module + LF bitstream) ---- */
#define T5577_MOD_KEY  "t5577"
#define T5577_MOD_PATH "/ramfs/rfid_t5577"
#define T5577_REQ      "/ramfs/.t5577req"      /* driver -> module: "<block> <hex32>" text */
#define LF_BAND        1                       /* BANDS[1] = LF (for its FPGA bitstream) */

static int obtain_t5577(const fantasi_api_t *api)
{
    if (api->file_size(T5577_MOD_PATH) >= 0) return 1;
    api->request_module(T5577_MOD_KEY);
    return obtain_wait(api, T5577_MOD_PATH);
}

/* `raw t5577 <block> <hex32>`: LF T5577 block write. The protocol lives entirely in the hot-loaded
 * t5577 module (which prints its own result); the driver just provisions the LF bitstream, pre-warms
 * it (freest-heap ordering, like do_raw), hands the module its request text, runs it, self-cleans. */
static void do_raw_t5577(const fantasi_api_t *api, const char *args)
{
    const fantasi_rfid_t *r = fantasi_rfid();
    if (!r || !r->lf_modulate) { api->print("t5577: LF transmit not supported on this device\r\n"); return; }
    if (!obtain_fpga(api, LF_BAND)) { api->print("disconnected: fpga bitstream unavailable\r\n"); return; }
    /* Warm the LF bitstream first, before obtain_t5577 stages the module file (heap ordering). */
    if (r->set_mode(FANTASI_RFID_LF_READER) != 0) { api->print("t5577: LF frontend unavailable\r\n"); return; }
    if (!obtain_t5577(api)) { api->print("disconnected: t5577 module unavailable\r\n"); return; }

    int len = 0; while (args[len]) len++;                  /* no libc strlen in module/driver land */
    api->write_file(T5577_REQ, args, (uint32_t)len);
    fantasi_run_module(T5577_MOD_PATH, api, true);
    s_field = 0;                                           /* the module powers the LF field down */

    api->remove(T5577_REQ);                                /* self-clean, like do_raw */
    api->remove(T5577_MOD_PATH);
}

/* ---- LF T5577 whole-tag read (bare `read t5577`): its own hot-loaded dump module ---- */
#define T5577_DUMP_MOD_KEY  "t5577_dump"
#define T5577_DUMP_MOD_PATH "/ramfs/rfid_t5577d"

static int obtain_t5577_dump(const fantasi_api_t *api)
{
    if (api->file_size(T5577_DUMP_MOD_PATH) >= 0) return 1;
    api->request_module(T5577_DUMP_MOD_KEY);
    return obtain_wait(api, T5577_DUMP_MOD_PATH);
}

/* `raw t5577dump`: read every physical T5577 block in one module invocation - provision the LF bitstream
 * and module once, then the module calibrates the block boundary once and reads all blocks, printing one
 * `t5577: p<page> b<block> = ...` line each. The host's bare `read t5577` sends this instead of looping 11
 * `raw t5577 N` commands (whose per-command module round-trip stalls on the transport). Self-cleans. */
static void do_raw_t5577_dump(const fantasi_api_t *api)
{
    const fantasi_rfid_t *r = fantasi_rfid();
    if (!r || !r->lf_transceive) { api->print("t5577: LF read not supported on this device\r\n"); return; }
    if (!obtain_fpga(api, LF_BAND)) { api->print("disconnected: fpga bitstream unavailable\r\n"); return; }
    if (r->set_mode(FANTASI_RFID_LF_READER) != 0) { api->print("t5577: LF frontend unavailable\r\n"); return; }
    if (!obtain_t5577_dump(api)) { api->print("disconnected: t5577 dump module unavailable\r\n"); return; }

    fantasi_run_module(T5577_DUMP_MOD_PATH, api, true);
    s_field = 0;                                           /* the module powers the LF field down */
    api->remove(T5577_DUMP_MOD_PATH);
}

/* ---- HF MIFARE Classic read: two hot-loaded /ramfs modules + HF bitstream ---- */
/* Split into a collect phase (PRNG sample, bootstrap a key, harvest nested nonces) and a read phase (auth +
 * block dump with host-solved keys). The offline work - PRNG classification and the dictionary match - runs
 * on the host, which also holds the dictionary, so the device carries neither the dict nor the matcher. Two
 * small modules each fit the /ramfs load budget. */
#define MFCC_MOD_KEY  "mfc_collect"
/* On LittleFS (flash), not /ramfs: the collect module carries the whole Hardnested collection state machine
 * (256-MSB coupon-collector loop, valid-sum check, nonce formatter) and is inherently ~5.5 KB - too big for
 * the fragmented /ramfs load budget, and its 256-nonce/target volume can't be formatted host-side through the
 * capture channel. Reading the ELF from flash keeps it off the heap during load. The read module is small and
 * stays in /ramfs; only this genuinely-large gather module needs flash. */
#define MFCC_MOD_PATH "/rfid_mfcc"
#define MFCR_MOD_KEY  "mfc_read"
/* Also on LittleFS (flash), not /ramfs: the read module carries the PRNG profiler + crypto1 (auth,
 * filter, prng_successor) alongside dict_check and the block dump, so its ELF is ~7 KB. Staged in /ramfs that ELF
 * would be heap, and heap + the ~5 KB load image together don't fit as a nested module. Reading from
 * flash keeps the ELF off the heap during load, exactly like the collect module above. */
#define MFCR_MOD_PATH "/rfid_mfcr"
#define HF_BAND      0                         /* BANDS[0] = HF (for its FPGA bitstream) */

static int obtain_named(const fantasi_api_t *api, const char *key, const char *path)
{
    if (api->file_size(path) >= 0) return 1;
    api->request_module(key);
    for (int waited = 0; api->file_size(path) < 0; ) {
        if (++waited > FETCH_LIMIT) return 0;
        api->delay(POLL_MS);
    }
    return 1;
}

/* `raw mfc collect` / `raw mfc read`: run one phase's module. The host orchestrates the two calls (collect ->
 * solve keys offline -> write the mfc_read keyfile -> read), provisioning the HF bitstream once. */
static void do_mfc(const fantasi_api_t *api, int phase)
{
    const fantasi_rfid_t *r = fantasi_rfid();
    if (!r) { api->print("mfc: not supported\r\n"); return; }
    if (!obtain_fpga(api, HF_BAND)) { api->print("disconnected: fpga bitstream unavailable\r\n"); return; }
    /* NOTE: do not set_mode(HF) here - the FPGA load needs a ~4 KB contiguous LZSS window, and the module
     * ELF is still resident in ramfs at this point, fragmenting the heap. fantasi_run_module frees the ELF
     * right after loading, so the module's own set_mode(HF) runs with room for the window. */
    const char *key  = phase ? MFCR_MOD_KEY  : MFCC_MOD_KEY;
    const char *path = phase ? MFCR_MOD_PATH : MFCC_MOD_PATH;
    if (!obtain_named(api, key, path)) { api->print("disconnected: mfc module unavailable\r\n"); return; }
    fantasi_run_module(path, api, true);
    s_field = 0;                                           /* the module powers HF down */
    api->remove(path);
}

/* ---- HF MIFARE Classic tag emulation ---- */
#define MFCE_MOD_KEY  "mfc_emu"
#define MFCE_MOD_PATH "/ramfs/rfid_mfce"

/* `raw mfcemu`: run the MIFARE Classic emulation module. The host has already staged the 1 KB card image at
 * /ramfs/mfc_emu.bin; we provision the HF bitstream (the module's set_mode(HF_EMU) reuses it) and run the
 * module, which load-modulates as a tag until the user presses a key. Self-cleans. */
static void do_emulate(const fantasi_api_t *api)
{
    const fantasi_rfid_t *r = fantasi_rfid();
    if (!r || !r->hf_emu_recv || !r->hf_emu_send) { api->print("emulate: not supported on this device\r\n"); return; }
    if (!obtain_fpga(api, HF_BAND)) { api->print("disconnected: fpga bitstream unavailable\r\n"); return; }
    if (!obtain_named(api, MFCE_MOD_KEY, MFCE_MOD_PATH)) { api->print("disconnected: emu module unavailable\r\n"); return; }
    fantasi_run_module(MFCE_MOD_PATH, api, true);
    s_field = 0;
    api->remove(MFCE_MOD_PATH);
}

/* Print buf[0..n) - the module's "<R|C> <hex>" frame lines - preceded by a `T`
 * header line so the host CLI tabulates them (CRC + protocol names) as a trace. */
static void emit_frames(const fantasi_api_t *api, const char *buf, int n)
{
    api->print("T\r\n");
    for (int i = 0; i < n; ) {
        int j = i;
        while (j < n && buf[j] != '\n') j++;
        if (j > i) {
            char line[128]; int l = j - i; if (l > (int)sizeof line - 1) l = (int)sizeof line - 1;
            for (int k = 0; k < l; k++) line[k] = buf[i + k];
            line[l] = '\0';
            api->printf("%s\r\n", line);
        }
        i = j + 1;
    }
}

/* `raw [-c][-k][-s] <hex>`: send a raw ISO14443-A frame (like pm3 hf 14a raw).
 * -c append CRC_A, -k keep the field on for follow-ups, -s select the card first
 * (pm3's letters: -s = field on with select, -c = CRC, -k = keep field). */
static void do_raw(const fantasi_api_t *api, const char *args)
{
    uint8_t req[80];
    uint32_t flags = 0;
    int nb = 0, nib = -1;
    /* optional leading <target>. "t5577" routes to the LF write module; "nfca"/"hf" select NFC-A
     * raw (the default) and are consumed - so `raw -c 3000` / `raw 3000` still work. Other protocol
     * tokens are mapped to their category host-side, so the device only sees nfca / t5577. */
    while (*args == ' ') args++;
    if (pop_word(&args, "t5577dump")) { do_raw_t5577_dump(api); return; }   /* bare `read t5577` whole-tag dump */
    if (pop_word(&args, "t5577")) { do_raw_t5577(api, args); return; }
    if (pop_word(&args, "mfccollect")) { do_mfc(api, 0); return; }   /* host `collect mfc card` -> nonce log */
    if (pop_word(&args, "mfcread"))    { do_mfc(api, 1); return; }   /* host `read mfc` -> dict dump */
    if (pop_word(&args, "mfcemu"))     { do_emulate(api); return; }  /* host `emulate mfc` -> tag emulation */
    if (!pop_word(&args, "nfca")) pop_word(&args, "hf");
    for (const char *p = args; *p; p++) {
        if (*p == ' ') continue;
        if (*p == '-') {
            for (p++; *p && *p != ' '; p++) {
                if      (*p == 'c') flags |= RAW_F_CRC;
                else if (*p == 'k') flags |= RAW_F_KEEP;
                else if (*p == 's') flags |= RAW_F_SELECT;
            }
            p--;
            continue;
        }
        int v = hexval(*p);
        if (v < 0) continue;
        if (nib < 0) nib = v;
        else if (nb < (int)sizeof req - 2) { req[2 + nb++] = (uint8_t)((nib << 4) | v); nib = -1; }
    }
    if (nb == 0 && !(flags & RAW_F_SELECT)) {
        api->print("usage: raw [-c][-k][-s] <hex>   (-c add CRC, -k keep field on, -s select first)\r\n");
        return;
    }
    /* Warm the HF bitstream first - before obtain_raw puts the 2.7 KB module file in ramfs - so
     * fpga_load's transient 4 KB config window allocates against the freest, least-fragmented heap
     * (only the driver + task stacks resident). Once it's cached, the module's own set_mode is a
     * no-op, so the module image and that window never occupy the heap together. Ordering matters:
     * with the module file already resident the window can't find 4 KB contiguous on the tight PM3
     * heap and set_mode returns RFID_ERR_UNSUPP -> the module aborts before it reads a card. */
    { const fantasi_rfid_t *r = fantasi_rfid(); if (r) r->set_mode(FANTASI_RFID_HF_READER); }

    if (!obtain_raw(api)) { api->print("disconnected: raw module unavailable\r\n"); return; }

    req[0] = (uint8_t)flags; req[1] = (uint8_t)nb;
    api->remove(RAW_LAST);
    api->write_file(RAW_REQ, req, (uint32_t)(2 + nb));
    fantasi_run_module(RAW_MOD_PATH, api, true);
    s_field = (flags & RAW_F_KEEP) ? 1 : 0;   /* the module leaves the field on only with -k */

    /* Read back the module's trace through a transient heap buffer - allocated only for this
     * command and freed before return, so it costs nothing on the tight PM3 heap while other
     * commands (notably sniff, which needs a big capture buffer) run. Allocated after the module
     * has unloaded, so it never competes with the module image. */
    char *buf = api->malloc(RAW_TRACE_BUF);
    int n = buf ? api->read_file(RAW_LAST, buf, RAW_TRACE_BUF) : -1;

    /* Free everything this command created - the request/result scratch and the module
     * file itself (re-fetched JIT next time, like do_scan). The module image is already
     * freed by app_run_module; leaving the 2.7 KB module file or the scratch resident
     * would fragment the tiny PM3 heap. Self-cleaning
     * per run means the heap returns to its between-command baseline, so nothing persists
     * to fragment a later run or the next session launch. */
    api->remove(RAW_REQ);
    api->remove(RAW_LAST);
    api->remove(RAW_MOD_PATH);

    if (n > 0) {
        emit_frames(api, buf, n);
        for (int i = 0; i < n && s_tracelen < (int)sizeof s_trace; i++) s_trace[s_tracelen++] = buf[i];
    } else {
        api->print(buf ? "no frames (field off, or no card in range)\r\n" : "raw: out of memory\r\n");
    }
    if (buf) api->free(buf);
}

/* `trace` replays the accumulated log; `trace clear` empties it. */
static void do_trace(const fantasi_api_t *api, const char *args)
{
    if (streq(args, "clear")) { s_tracelen = 0; api->print("trace cleared\r\n"); return; }
    if (s_tracelen == 0)      { api->print("trace empty\r\n"); return; }
    emit_frames(api, s_trace, s_tracelen);
}

/* `field on|off|status`: drive the reader carrier directly (leave it on to keep a
 * card powered between raw commands, or off to release it) or report its state. */
static void do_field(const fantasi_api_t *api, const char *arg)
{
    const fantasi_rfid_t *r = fantasi_rfid();
    if (!r || !(r->caps() & FANTASI_RFID_CAP_HF_READ)) { api->print("field: HF reader unavailable\r\n"); return; }
    if (streq(arg, "status")) { api->printf("field is %s\r\n", s_field ? "on" : "off"); return; }
    if (streq(arg, "off")) { r->field(0); r->set_mode(FANTASI_RFID_OFF); s_field = 0; api->print("field off\r\n"); return; }
    if (streq(arg, "on") || arg[0] == '\0') {
        if (r->set_mode(FANTASI_RFID_HF_READER) != 0) { api->print("field: HF frontend unavailable\r\n"); return; }
        r->field(1); s_field = 1; api->print("field on\r\n"); return;
    }
    api->print("usage: field on|off|status\r\n");
}

/* Run one command line. Returns 1 to keep the sub-CLI running, 0 to exit. */
static int dispatch(const fantasi_api_t *api, const char *line)
{
    const char *a;
    if (line[0] == '\0')                              return 1;
    if ((a = cmd_args(line, "search"))) { scan(api, a); return 1; }
    if ((a = cmd_args(line, "sniff")))  { do_sniff(api, a); return 1; }
    if ((a = cmd_args(line, "raw")))    { do_raw(api, a);   return 1; }
    if ((a = cmd_args(line, "trace")))  { do_trace(api, a); return 1; }
    if ((a = cmd_args(line, "field")))  { do_field(api, a); return 1; }
    if (streq(line, "exit") || streq(line, "quit")) return 0;
    api->printf("unknown command '%s' (try: help)\r\n", line);
    return 1;
}

int app_main(const fantasi_api_t *api)
{
    if (!fantasi_rfid()) { api->print("rfid: no RFID on this device\r\n"); return 1; }
    if (api->abi_version < 3 || !api->read_input || !api->request_module) {
        api->print("rfid: firmware too old (needs async app sessions)\r\n");
        return 1;
    }

    /* This app is driven only through the host CLI (the async session needs the device RX loop free,
     * which raw serial can't give). The host owns the line editing with readline, so the app does not
     * echo or handle backspace - it just accumulates a clean line and dispatches on newline. PROMPT is
     * the host's cue that the app is ready for the next line (it shows its own readline prompt). */
    api->print(PROMPT);

    char line[LINE_MAX];
    int len = 0;
    for (;;) {
        char buf[32];
        int n = api->read_input(buf, sizeof buf);
        if (n <= 0) { api->delay(15); continue; }

        for (int i = 0; i < n; i++) {
            char c = buf[i];
            if (c == '\r' || c == '\n') {
                line[len] = '\0';
                while (len > 0 && line[len-1] == ' ') line[--len] = '\0';   /* trim the trailing space a
                                                       * completed command carries, so exact-match dispatch
                                                       * still recognises "sniff" / "field status" */
                len = 0;
                if (!dispatch(api, line)) {
                    const fantasi_rfid_t *r = fantasi_rfid();   /* release the field a -k raw left on */
                    if (r) { r->field(0); r->set_mode(FANTASI_RFID_OFF); }
                    return 0;
                }
                api->print(PROMPT);
            } else if (c == 0x7f || c == 0x08) {          /* backspace (robustness; readline normally resolves it) */
                if (len > 0) len--;
            } else if ((unsigned char)c >= 0x20 && (unsigned char)c < 0x7f) {
                if (len < LINE_MAX - 1) line[len++] = c;   /* accumulate, no echo */
            }
            /* other control bytes ignored */
        }
    }
}
