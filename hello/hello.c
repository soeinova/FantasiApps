/* Hello world - reference Fantasi app. Prints a greeting, exercises the heap, and
 * returns an exit code. Doubles as the loader spike / end-to-end test fixture. */
#include "app_api.h"

static const char greeting[] = "hello from a Fantasi app\n";

int app_main(const fantasi_api_t *api)
{
    api->print(greeting);

    char *buf = api->malloc(32);
    if (buf) {
        for (int i = 0; i < 31; i++)
            buf[i] = 'x';
        buf[31] = '\0';
        api->print(buf);
        api->print("\n");
        api->free(buf);
    }

    api->printf("abi=%u\n", (unsigned)api->abi_version);
    return 42;
}
