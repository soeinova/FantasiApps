/* hellogui - draws "Hello GUI" on the device screen and holds it until ^C.
 * Demonstrates the optional display_* app API: those pointers are NULL on a
 * device without a panel (e.g. Chameleon Ultra, Proxmark3), so guard before
 * calling. On the Flipper Zero the firmware bridges them to the 128x64 LCD and,
 * for the app's lifetime, suspends its own status/splash redraw so it can't
 * paint over us (see hal_app_display_acquire/release). */
#include "app_api.h"

int app_main(const fantasi_api_t *api)
{
    if (!api->display_print || !api->display_clear || !api->display_flush) {
        api->print("this device has no display\n");
        return 1;
    }

    /* col is a pixel X (0..127), row a text line (0..7). "Hello GUI" is 9 chars
     * * 6 px = 54 px wide, so x = (128 - 54) / 2 = 37 centers it; row 3 is the
     * vertical middle of the 8-line panel. */
    api->display_clear();
    api->display_print(37, 3, "Hello GUI");
    api->display_flush();

    api->print("drew \"Hello GUI\" - it stays on screen until you press ^C\n");

    /* Hold the screen so the persistence is visible, without spinning: delay()
     * sleeps this app and yields the CPU (and lets the core idle). The launch
     * session watches for ^C and reclaims us, so this loop can't stall the CLI. */
    for (;;)
        api->delay(200);

    return 0;   /* unreachable; ^C ends the app */
}
