/* BadUSB - turns the device into a USB keyboard that types out scripts,
 * Rubber Ducky style.
 *
 * Scripts live in /badusb/ and are either Berry (.be) or classic Duckyscript
 * (.txt). This file is the app side: it maps characters and key names to USB
 * keycodes, runs the chosen script, and gives Berry scripts a `hid` module to
 * type with. Actually sending the keystrokes over USB is the firmware's job -
 * the app calls api->hid_mode / hid_send / hid_host for that.
 *
 * The Berry interpreter itself lives in the firmware; the be_* calls in this
 * file are hooked up to it by the ELF loader when the app is loaded. */
#include "app_api.h"
#include "berry.h"

/* Firmware `hardware` module installer (buttons/LEDs), resolved by the loader. */
extern void berry_install_hardware(bvm *vm);

#define BADUSB_VERSION  "v1.0.0"
#define BADUSB_DIR      "/badusb"
#define CFG_PATH        "/badusb/badusb.cfg"
#define MAX_SCRIPTS     24
#define NAME_LEN        40

static const fantasi_api_t *g_api;

/* ---------------------------------------------------------------------------
 * Tiny freestanding string helpers (the app links -nostdlib).
 * ------------------------------------------------------------------------- */
static char up(char c) { return (c >= 'a' && c <= 'z') ? (char)(c - 32) : c; }

static int ci_eq(const char *a, const char *b)
{
    while (*a && *b) { if (up(*a) != up(*b)) return 0; a++; b++; }
    return *a == *b;
}

static unsigned to_uint(const char *s)
{
    unsigned v = 0;
    while (*s == ' ') s++;
    while (*s >= '0' && *s <= '9') { v = v * 10u + (unsigned)(*s - '0'); s++; }
    return v;
}

static void copystr(char *dst, unsigned cap, const char *src)
{
    unsigned i = 0;
    for (; src[i] && i < cap - 1; i++) dst[i] = src[i];
    dst[i] = 0;
}

static int ends_with(const char *s, const char *sfx)
{
    unsigned n = 0, m = 0;
    while (s[n]) n++;
    while (sfx[m]) m++;
    if (n < m) return 0;
    for (unsigned i = 0; i < m; i++) if (s[n - m + i] != sfx[i]) return 0;
    return 1;
}

static void join_path(char *out, unsigned cap, const char *dir, const char *name)
{
    unsigned o = 0;
    for (unsigned i = 0; dir[i] && o < cap - 1; i++) out[o++] = dir[i];
    if (o && out[o - 1] != '/' && o < cap - 1) out[o++] = '/';
    for (unsigned i = 0; name[i] && o < cap - 1; i++) out[o++] = name[i];
    out[o] = 0;
}

/* ---------------------------------------------------------------------------
 * US ASCII / named-key -> HID keycode (the app's keymap, driving the module).
 * ------------------------------------------------------------------------- */
static int ascii_to_key(char c, uint8_t *mod, uint8_t *key)
{
    *mod = 0; *key = 0;
    if (c >= 'a' && c <= 'z') { *key = (uint8_t)(0x04 + (c - 'a')); return 1; }
    if (c >= 'A' && c <= 'Z') { *key = (uint8_t)(0x04 + (c - 'A')); *mod = FANTASI_HID_LSHIFT; return 1; }
    if (c >= '1' && c <= '9') { *key = (uint8_t)(0x1E + (c - '1')); return 1; }
    switch (c) {
    case '0':  *key = 0x27; return 1;
    case ' ':  *key = 0x2C; return 1;
    case '\t': *key = 0x2B; return 1;
    case '\n': *key = 0x28; return 1;
    case '-':  *key = 0x2D; return 1;
    case '_':  *key = 0x2D; *mod = FANTASI_HID_LSHIFT; return 1;
    case '=':  *key = 0x2E; return 1;
    case '+':  *key = 0x2E; *mod = FANTASI_HID_LSHIFT; return 1;
    case '[':  *key = 0x2F; return 1;
    case '{':  *key = 0x2F; *mod = FANTASI_HID_LSHIFT; return 1;
    case ']':  *key = 0x30; return 1;
    case '}':  *key = 0x30; *mod = FANTASI_HID_LSHIFT; return 1;
    case '\\': *key = 0x31; return 1;
    case '|':  *key = 0x31; *mod = FANTASI_HID_LSHIFT; return 1;
    case ';':  *key = 0x33; return 1;
    case ':':  *key = 0x33; *mod = FANTASI_HID_LSHIFT; return 1;
    case '\'': *key = 0x34; return 1;
    case '"':  *key = 0x34; *mod = FANTASI_HID_LSHIFT; return 1;
    case '`':  *key = 0x35; return 1;
    case '~':  *key = 0x35; *mod = FANTASI_HID_LSHIFT; return 1;
    case ',':  *key = 0x36; return 1;
    case '<':  *key = 0x36; *mod = FANTASI_HID_LSHIFT; return 1;
    case '.':  *key = 0x37; return 1;
    case '>':  *key = 0x37; *mod = FANTASI_HID_LSHIFT; return 1;
    case '/':  *key = 0x38; return 1;
    case '?':  *key = 0x38; *mod = FANTASI_HID_LSHIFT; return 1;
    case '!':  *key = 0x1E; *mod = FANTASI_HID_LSHIFT; return 1;
    case '@':  *key = 0x1F; *mod = FANTASI_HID_LSHIFT; return 1;
    case '#':  *key = 0x20; *mod = FANTASI_HID_LSHIFT; return 1;
    case '$':  *key = 0x21; *mod = FANTASI_HID_LSHIFT; return 1;
    case '%':  *key = 0x22; *mod = FANTASI_HID_LSHIFT; return 1;
    case '^':  *key = 0x23; *mod = FANTASI_HID_LSHIFT; return 1;
    case '&':  *key = 0x24; *mod = FANTASI_HID_LSHIFT; return 1;
    case '*':  *key = 0x25; *mod = FANTASI_HID_LSHIFT; return 1;
    case '(':  *key = 0x26; *mod = FANTASI_HID_LSHIFT; return 1;
    case ')':  *key = 0x27; *mod = FANTASI_HID_LSHIFT; return 1;
    }
    return 0;
}

static int named_key(const char *t, uint8_t *key)
{
    static const struct { const char *n; uint8_t k; } tbl[] = {
        { "ENTER", 0x28 }, { "RETURN", 0x28 }, { "ESC", 0x29 }, { "ESCAPE", 0x29 },
        { "BACKSPACE", 0x2A }, { "TAB", 0x2B }, { "SPACE", 0x2C },
        { "CAPSLOCK", 0x39 }, { "PRINTSCREEN", 0x46 }, { "SCROLLLOCK", 0x47 },
        { "PAUSE", 0x48 }, { "BREAK", 0x48 }, { "INSERT", 0x49 }, { "HOME", 0x4A },
        { "PAGEUP", 0x4B }, { "DELETE", 0x4C }, { "DEL", 0x4C }, { "END", 0x4D },
        { "PAGEDOWN", 0x4E }, { "RIGHT", 0x4F }, { "RIGHTARROW", 0x4F },
        { "LEFT", 0x50 }, { "LEFTARROW", 0x50 }, { "DOWN", 0x51 }, { "DOWNARROW", 0x51 },
        { "UP", 0x52 }, { "UPARROW", 0x52 }, { "NUMLOCK", 0x53 },
        { "MENU", 0x65 }, { "APP", 0x65 },
    };
    for (unsigned i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++)
        if (ci_eq(t, tbl[i].n)) { *key = tbl[i].k; return 1; }
    if ((t[0] == 'F' || t[0] == 'f') && t[1]) {
        unsigned n = to_uint(t + 1);
        if (n >= 1 && n <= 12) { *key = (uint8_t)(0x3A + (n - 1)); return 1; }
    }
    return 0;
}

static uint8_t mod_of(const char *t)
{
    if (ci_eq(t, "CTRL") || ci_eq(t, "CONTROL")) return FANTASI_HID_LCTRL;
    if (ci_eq(t, "SHIFT")) return FANTASI_HID_LSHIFT;
    if (ci_eq(t, "ALT")) return FANTASI_HID_LALT;
    if (ci_eq(t, "GUI") || ci_eq(t, "WINDOWS") || ci_eq(t, "WIN") ||
        ci_eq(t, "COMMAND") || ci_eq(t, "META")) return FANTASI_HID_LGUI;
    return 0;
}

/* ---- report delivery ---- */
static void combo_tap(uint8_t mod, uint8_t key)
{
    uint8_t k[1] = { key };
    g_api->hid_send(mod, key ? k : 0, key ? 1 : 0);
    g_api->hid_send(0, 0, 0);   /* release */
}

static void type_string(const char *s)
{
    for (; s && *s; s++) {
        uint8_t mod, key;
        if (ascii_to_key(*s, &mod, &key)) combo_tap(mod, key);
    }
}

/* ---------------------------------------------------------------------------
 * The native `hid` Berry module. Berry args are 1-indexed.
 * ------------------------------------------------------------------------- */
static int l_mode(bvm *vm)   { g_api->hid_mode(be_tobool(vm, 1)); be_return_nil(vm); }
static int l_delay(bvm *vm)  { g_api->delay((uint32_t)be_toint(vm, 1)); be_return_nil(vm); }
static int l_string(bvm *vm) { type_string(be_tostring(vm, 1)); be_return_nil(vm); }
static int l_host(bvm *vm)   { be_pushint(vm, (bint)g_api->hid_host()); be_return(vm); }

/* hid.key("ENTER") / hid.key("a") / hid.key(0x28) - a named key, a single char,
 * or a raw keycode. */
static int l_key(bvm *vm)
{
    uint8_t mod = 0, key = 0, cm, ck;
    if (be_isstring(vm, 1)) {
        const char *t = be_tostring(vm, 1);
        if (named_key(t, &ck)) key = ck;
        else if (t[0] && !t[1] && ascii_to_key(t[0], &cm, &ck)) { key = ck; mod = cm; }
    } else {
        key = (uint8_t)be_toint(vm, 1);
    }
    combo_tap(mod, key);
    be_return_nil(vm);
}

/* hid.combo("GUI r")  /  hid.combo("CTRL ALT DELETE") - a space-separated combo:
 * modifiers held together with the final key. A single string so it reads well
 * in scripts and lets the Duckyscript shim pass a raw line. */
static int l_combo(bvm *vm)
{
    const char *line = be_tostring(vm, 1);
    if (!line) be_return_nil(vm);

    char buf[128];
    unsigned n = 0;
    for (; line[n] && n < sizeof(buf) - 1; n++) buf[n] = line[n];
    buf[n] = 0;

    uint8_t mod = 0, key = 0, cm, ck;
    char *p = buf;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;
        char *tok = p;
        while (*p && *p != ' ') p++;
        char save = *p; *p = 0;
        uint8_t m = mod_of(tok);
        if (m) mod |= m;
        else if (named_key(tok, &ck)) key = ck;
        else if (tok[0] && !tok[1] && ascii_to_key(tok[0], &cm, &ck)) { key = ck; mod |= cm; }
        *p = save;
    }
    combo_tap(mod, key);
    be_return_nil(vm);
}

static void add_fn(bvm *vm, const char *name, bntvfunc fn)
{
    be_pushntvfunction(vm, fn);
    be_setmember(vm, -2, name);   /* set module.<name> = fn (does not pop) */
    be_pop(vm, 1);
}

/* Build the `hid` module and expose it as a global. */
static void register_hid(bvm *vm)
{
    be_newmodule(vm);
    add_fn(vm, "mode",   l_mode);
    add_fn(vm, "delay",  l_delay);
    add_fn(vm, "string", l_string);
    add_fn(vm, "key",    l_key);
    add_fn(vm, "combo",  l_combo);
    add_fn(vm, "host",   l_host);
    be_setglobal(vm, "hid");
    be_pop(vm, 1);
}

/* ---------------------------------------------------------------------------
 * Screen helpers (no-op without a display).
 * ------------------------------------------------------------------------- */
static int has_screen(void) { return g_api->display_print != 0; }

static void status2(const char *a, const char *b)
{
    if (!has_screen()) return;
    g_api->display_clear();
    g_api->display_print(0, 0, a);
    if (b) g_api->display_print(0, 2, b);
    g_api->display_flush();
}

/* ---------------------------------------------------------------------------
 * Run a Berry payload: arm HID, run the script with the `hid` module, disarm.
 * ------------------------------------------------------------------------- */
static int run_script(const char *path, const char *shortname)
{
    if (g_api->file_size(path) <= 0) {
        g_api->printf("BadUSB: cannot open %s\n", path);
        status2("BadUSB: error", shortname ? shortname : path);
        return -1;
    }

    g_api->printf("BadUSB: running %s\n", path);
    status2("BadUSB: running", shortname ? shortname : path);

    if (g_api->hid_mode(1) != 0) {
        g_api->print("BadUSB: USB HID not available on this device\n");
        status2("HID unavailable", 0);
        return -1;
    }
    g_api->delay(200);

    int rc = -1;
    bvm *vm = be_vm_new();
    if (!vm) {
        g_api->print("BadUSB: Berry VM out of memory\n");
    } else {
        register_hid(vm);
        berry_install_hardware(vm);   /* buttons/LEDs available to payloads too */
        if (ends_with(path, ".txt")) {
            /* Legacy Duckyscript: hand the path to the Berry shim via a global. */
            be_pushstring(vm, path);
            be_setglobal(vm, "_ducky");
            be_pop(vm, 1);
            rc = be_loadfile(vm, BADUSB_DIR "/duckyscript/duckyscript.be");
        } else {
            rc = be_loadfile(vm, path);
        }
        if (rc == 0) rc = be_pcall(vm, 0);
        if (rc != 0) {
            const char *e = be_tostring(vm, -1);
            g_api->printf("berry: %s\n", e ? e : "error");
        }
        be_vm_delete(vm);
    }

    g_api->hid_mode(0);
    g_api->print("BadUSB: done\n");
    status2("BadUSB: done", shortname ? shortname : 0);
    return rc;
}

/* ---------------------------------------------------------------------------
 * Config + first-run setup.
 * ------------------------------------------------------------------------- */
/* The Duckyscript-1.0 interpreter, written in Berry. BadUSB drops it in
 * /badusb/duckyscript/ on first run and runs it (with the global `_ducky` set to
 * the .txt path) whenever a .txt payload is selected - legacy compatibility
 * without a C parser. Users can read or tweak it. */
static const char DUCKY_SHIM[] =
    "# duckyscript.be - run a legacy Duckyscript (.txt) via the hid module.\n"
    "# BadUSB sets the global _ducky to the .txt path before running this.\n"
    "import string\n"
    "if _ducky == nil return end\n"
    "var f = open(_ducky, 'r')\n"
    "if f == nil print('duckyscript: cannot open', _ducky) return end\n"
    "var ddelay = 0\n"
    "var last = nil\n"
    "def run_line(line)\n"
    "  var sp = string.find(line, ' ')\n"
    "  var cmd = sp < 0 ? line : line[0..sp-1]\n"
    "  var arg = sp < 0 ? '' : line[sp+1..]\n"
    "  cmd = string.toupper(cmd)\n"
    "  if cmd == '' || cmd == 'REM' return false end\n"
    "  if cmd == 'DEFAULT_DELAY' || cmd == 'DEFAULTDELAY' ddelay = int(arg) return false end\n"
    "  if cmd == 'DELAY' last = line hid.delay(int(arg)) return true end\n"
    "  if cmd == 'STRING' last = line hid.string(arg) return true end\n"
    "  if cmd == 'STRINGLN' last = line hid.string(arg) hid.key('ENTER') return true end\n"
    "  if cmd == 'REPEAT'\n"
    "    if last != nil\n"
    "      var l = last var n = int(arg) var i = 0\n"
    "      while i < n run_line(l) hid.delay(ddelay) i += 1 end\n"
    "    end\n"
    "    return false\n"
    "  end\n"
    "  last = line\n"
    "  hid.combo(line)\n"
    "  return true\n"
    "end\n"
    "var line = f.readline()\n"
    "while line != nil\n"
    "  while size(line) > 0 && (line[-1] == '\\n' || line[-1] == '\\r') line = line[0..-2] end\n"
    "  if run_line(line) hid.delay(ddelay) end\n"
    "  line = f.readline()\n"
    "end\n"
    "f.close()\n";

static void first_run_setup(void)
{
    if (g_api->file_size(CFG_PATH) >= 0) return;   /* already set up */

    g_api->mkdir(BADUSB_DIR);
    g_api->mkdir(BADUSB_DIR "/duckyscript");
    g_api->write_file(BADUSB_DIR "/duckyscript/duckyscript.be", DUCKY_SHIM, sizeof(DUCKY_SHIM) - 1);

    static const char cfg[] =
        "# BadUSB configuration\r\n"
        "# autorun: a .be payload to run automatically on launch (empty = menu)\r\n"
        "autorun=\r\n"
        "script_dir=/badusb\r\n";
    g_api->write_file(CFG_PATH, cfg, sizeof(cfg) - 1);

    static const char sample[] =
        "# BadUSB sample payload (Berry). Types over the emulated keyboard.\r\n"
        "hid.delay(500)\r\n"
        "hid.string('hello from BadUSB via Berry')\r\n"
        "hid.key('ENTER')\r\n"
        "for i : 1 .. 3\r\n"
        "  hid.string('line ' + str(i))\r\n"
        "  hid.key('ENTER')\r\n"
        "end\r\n";
    g_api->write_file(BADUSB_DIR "/hello.be", sample, sizeof(sample) - 1);
}

static void load_config(char *autorun, unsigned acap, char *dir, unsigned dcap)
{
    copystr(dir, dcap, BADUSB_DIR);
    autorun[0] = 0;

    int32_t sz = g_api->file_size(CFG_PATH);
    if (sz < 0) return;
    char *buf = g_api->malloc((uint32_t)sz + 1);
    if (!buf) return;
    int32_t rd = g_api->read_file(CFG_PATH, buf, (uint32_t)sz);
    if (rd < 0) { g_api->free(buf); return; }
    buf[rd] = 0;

    char *line = buf;
    while (*line) {
        char *nl = line;
        while (*nl && *nl != '\n') nl++;
        char had = *nl;
        *nl = 0;
        if (nl > line && nl[-1] == '\r') nl[-1] = 0;
        char *p = line;
        while (*p == ' ') p++;
        if (*p && *p != '#') {
            char *eq = p;
            while (*eq && *eq != '=') eq++;
            if (*eq == '=') {
                *eq = 0;
                char *val = eq + 1;
                while (*val == ' ') val++;
                if (ci_eq(p, "autorun")) copystr(autorun, acap, val);
                else if (ci_eq(p, "script_dir") && *val) copystr(dir, dcap, val);
            }
        }
        if (!had) break;
        line = nl + 1;
    }
    g_api->free(buf);
}

/* ---------------------------------------------------------------------------
 * Script discovery + on-screen picker.
 * ------------------------------------------------------------------------- */
static char g_names[MAX_SCRIPTS][NAME_LEN];
static int  g_count;

static void collect_cb(const char *name, uint32_t size, int is_dir, void *ctx)
{
    (void)size; (void)ctx;
    if (is_dir) return;
    /* Both payload formats: .be (Berry) and .txt (Duckyscript). run_script picks
     * the interpreter by extension, so the picker can list and launch either. */
    if (!ends_with(name, ".be") && !ends_with(name, ".txt")) return;
    if (g_count >= MAX_SCRIPTS) return;
    copystr(g_names[g_count], NAME_LEN, name);
    g_count++;
}

static void draw_picker(int sel, int top)
{
    g_api->display_clear();
    g_api->display_print(0, 0, "BadUSB " BADUSB_VERSION);
    if (g_count == 0) {
        g_api->display_print(0, 2, "No scripts in");
        g_api->display_print(0, 3, BADUSB_DIR);
    } else {
        for (int i = 0; i < 7 && top + i < g_count; i++) {
            int r = top + i;
            char row[24];
            row[0] = (r == sel) ? '>' : ' ';
            row[1] = ' ';
            unsigned o = 2;
            for (unsigned k = 0; g_names[r][k] && o < 21; k++) row[o++] = g_names[r][k];
            row[o] = 0;
            g_api->display_print(0, 1 + i, row);
        }
    }
    g_api->display_flush();
}

static void ui_picker(const char *dir)
{
    int sel = 0, top = 0, dirty = 1;
    uint32_t prev = g_api->buttons();
    for (;;) {
        if (dirty) { draw_picker(sel, top); dirty = 0; }
        uint32_t b = g_api->buttons();
        uint32_t pressed = b & ~prev;
        prev = b;
        if (pressed & FANTASI_BTN_BACK) return;
        if (g_count) {
            if (pressed & FANTASI_BTN_DOWN) {
                if (sel < g_count - 1) { sel++; if (sel >= top + 7) top = sel - 6; }
                dirty = 1;
            } else if (pressed & FANTASI_BTN_UP) {
                if (sel > 0) { sel--; if (sel < top) top = sel; }
                dirty = 1;
            } else if (pressed & FANTASI_BTN_OK) {
                char full[160];
                join_path(full, sizeof full, dir, g_names[sel]);
                run_script(full, g_names[sel]);
                prev = g_api->buttons();
                dirty = 1;
            }
        }
        g_api->delay(30);
    }
}

/* ------------------------------------------------------------------------- */
int app_main(const fantasi_api_t *api)
{
    g_api = api;
    api->print("BadUSB " BADUSB_VERSION " - Berry-scripted USB HID keyboard\n");

    if (api->abi_version < 2 || !api->hid_mode) {
        api->print("BadUSB: needs firmware ABI >= 2 (HID).\n");
        return 1;
    }

    first_run_setup();

    char dir[64], autorun[96];
    load_config(autorun, sizeof autorun, dir, sizeof dir);

    if (autorun[0]) {
        char full[160];
        if (autorun[0] == '/') copystr(full, sizeof full, autorun);
        else join_path(full, sizeof full, dir, autorun);
        return run_script(full, autorun);
    }

    g_count = 0;
    if (api->list_dir(dir, collect_cb, 0) != 0)
        api->printf("BadUSB: no script directory %s\n", dir);

    if (has_screen()) {
        ui_picker(dir);
        return 0;
    }

    if (g_count == 1) {
        char full[160];
        join_path(full, sizeof full, dir, g_names[0]);
        return run_script(full, g_names[0]);
    }
    api->printf("BadUSB: %d payload(s) in %s:\n", g_count, dir);
    for (int i = 0; i < g_count; i++) api->printf("  %s\n", g_names[i]);
    api->print("Set 'autorun=<name>' in " CFG_PATH " to run one automatically.\n");
    return 0;
}
