# Fantasi app repository

## Getting started

Each app lives in its own root-level directory:

```
<app>/<app>.c      app source (entry point: app_main)
<app>/app.json     metadata; the "id" field names the build output
                   (validated: must match ^[A-Za-z0-9_-]+$)
```

The top-level `apps.json` is the launcher's app index: each entry points to an
app by `id`, with its `metadata` field naming the app's JSON file (a bare
filename, e.g. `hello.json`). It is authored here and synced to
fantasi.cloud's launcher on deploy - add your app to it to make it show up.

## Building locally

Requires `arm-none-eabi-gcc` on PATH and a checkout of the Fantasi tree for
the app SDK (`apps/app_api.h`, `apps/app.ld`):

```
make app APP=hello FANTASI=/path/to/Fantasi   # one app (FANTASI defaults to ../Fantasi)
make all                                      # every app
make clean
```

Each app produces one relocatable ELF per supported architecture in `build/`:

```
build/<Name>.cm4.elf    Cortex-M4 / ARMv7E-M  (Flipper Zero, Kiisu, Chameleon Ultra)
build/<Name>.arm7.elf   ARM7TDMI / ARMv4T     (Proxmark3)
```

Upload the variant matching your target to `/ramfs` or `/apps`, then `launch` it.

## CI

Every push runs `.github/workflows/build.yml`, which builds only the apps
whose files changed in that push (changes to the Makefile or the workflow
rebuild everything, as do new branches, force pushes, and manual
`workflow_dispatch` runs). The resulting ELFs are published as a single
`build` artifact (downloads as `build.zip`) on the action run.
