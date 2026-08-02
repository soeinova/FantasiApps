# Build a Fantasi app from this repo into loadable ELF(s):  make app APP=hello
#
# Apps live at the repo root as <app>/<app>.c with metadata in <app>/app.json.
# A multi-file app may also carry feature modules under <app>/modules/*.c: the
# main <app>.c is built to <id>.elf and each module to its own <basename>.elf,
# which the on-device driver hot-loads by that basename (e.g. rfid + hf/lf/...).
# Apps are freestanding, relocatable ARM objects (one ET_REL object, relocations
# collapsed to R_ARM_ABS32 + the harmless R_ARM_V4BX marker). The binary is
# architecture-specific, so this builds one ELF per supported core, named after
# the "id" field of the app's app.json:
#
#   build/<Name>.cm4.elf   Cortex-M4 / ARMv7E-M  (Flipper, Chameleon)
#   build/<Name>.arm7.elf  ARM7TDMI / ARMv4T     (Proxmark3)
#
# The Fantasi tree supplies the app SDK (apps/app_api.h and apps/app.ld); point
# FANTASI at a checkout of it (defaults to a sibling ../Fantasi).
#
#   make app APP=hello        build one app
#   make all                  build every app (any root dir with an app.json)
#   make clean                remove build/

FANTASI ?= ../Fantasi
SDK     := $(FANTASI)/apps
# Apps that embed Berry (e.g. badusb, which defines native Berry modules) include
# berry.h; the Berry headers live in the Fantasi tree under third_party/berry.
BERRY   := $(FANTASI)/third_party/berry
BUILD   := build
APP     ?=

CROSS ?= arm-none-eabi-
CC    := $(CROSS)gcc
LD    := $(CROSS)ld

# Every root-level directory holding an app.json is an app. APP is only
# accepted if it is one of these, so it can never name a path outside the repo.
ALL_APPS  := $(patsubst %/app.json,%,$(wildcard */app.json))
VALID_APP := $(filter $(APP),$(ALL_APPS))

# Flags shared by every variant. -mword-relocations + -mlong-calls force all
# address references (data and calls) through relocated literals, so the loader
# only ever sees R_ARM_ABS32 (plus R_ARM_V4BX on ARMv4T, which it ignores).
# Optimisation level is per-core (below), NOT here: cm4 (Flipper/Chameleon, ample RAM) builds -O2 for speed -
# it materially lowers the tag-emulation FDT by fully inlining the per-symbol reply producer - while arm7
# (Proxmark3, tight ramfs heap) stays -Os for size.
COMMON := -ffreestanding -fno-common -mword-relocations -mlong-calls \
          -ffunction-sections -fdata-sections -nostdlib -Wall -I$(SDK) \
          -I$(APP) -I$(APP)/modules \
          -I$(BERRY) -I$(BERRY)/src

# Per-core flags. Cortex-M is Thumb-2 + hard FP; ARM7TDMI is ARM-mode + interwork.
# -DEMU_STREAM_BUF (cm4 only): compiles the mfc_emu crypto-reply BUFFER fallback needed by CPU-bit-banged
# frontends (Flipper) that can't overlap the producer with TX. Harmless to apps that don't use it; the ARM7
# build (Proxmark3, RAM-tight) omits it so its module carries only the streaming path.
CM4_FLAGS  := -O2 -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16 -DEMU_STREAM_BUF
ARM7_FLAGS := -Os -mcpu=arm7tdmi -mthumb-interwork

.PHONY: all app clean
all:
	@for a in $(ALL_APPS); do \
	  $(MAKE) --no-print-directory app APP=$$a || exit 1; \
	done

# The output basename is the "id" field of <app>/app.json. app.json is repo
# content, so the value is treated as untrusted: it is extracted and validated
# entirely inside one quoted shell variable (never round-tripped through make
# expansion, which would allow recipe injection) and must match
# ^[A-Za-z0-9_-]+$ - no '/', '.', or anything else that could smuggle path
# components into the output path. Extracted with sed, not a JSON parser,
# because the app.json files carry trailing commas.
app:
	@test -n "$(APP)" || { echo "usage: make app APP=<name>  (source: <name>/<name>.c)"; exit 1; }
	@test -n "$(VALID_APP)" || { echo "error: APP must be a root-level app directory containing app.json (one of: $(ALL_APPS))"; exit 1; }
	@test -f $(APP)/$(APP).c || { echo "error: $(APP)/$(APP).c not found"; exit 1; }
	@test -f $(SDK)/app_api.h || { echo "error: Fantasi SDK not found at $(SDK) - set FANTASI=/path/to/Fantasi"; exit 1; }
	@name="$$(sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' $(APP)/app.json | head -n1 | tr -d '[:space:]')"; \
	case "$$name" in \
	  '') echo 'error: no "id" field in $(APP)/app.json' >&2; exit 1;; \
	  *[!A-Za-z0-9_-]*) echo "error: app id '$$name' in $(APP)/app.json is invalid: it must contain only [A-Za-z0-9_-]" >&2; exit 1;; \
	esac; \
	mkdir -p $(BUILD) && \
	$(MAKE) --no-print-directory _variant APP=$(APP) SRC="$(APP)/$(APP).c" BASE="$$name" VARIANT=cm4  VFLAGS="$(CM4_FLAGS)"  && \
	$(MAKE) --no-print-directory _variant APP=$(APP) SRC="$(APP)/$(APP).c" BASE="$$name" VARIANT=arm7 VFLAGS="$(ARM7_FLAGS)" && \
	for m in $(APP)/modules/*.c; do [ -e "$$m" ] || continue; b="$$(basename "$$m" .c)"; \
	  $(MAKE) --no-print-directory _variant APP=$(APP) SRC="$$m" BASE="$$b" VARIANT=cm4  VFLAGS="$(CM4_FLAGS)"  || exit 1; \
	  $(MAKE) --no-print-directory _variant APP=$(APP) SRC="$$m" BASE="$$b" VARIANT=arm7 VFLAGS="$(ARM7_FLAGS)" || exit 1; \
	done && \
	echo "built $(BUILD)/$$name.{cm4,arm7}.elf$$( [ -d $(APP)/modules ] && echo ' + modules/ (by basename)' )"

# Internal: build one source file into one architecture variant. The app's main is built as $(APP)/$(APP).c
# named by the app.json "id" (BASE); feature modules under $(APP)/modules/ are each built by their .c basename
# (the on-device driver hot-loads them by that name), so one app can span the driver + several module ELFs.
.PHONY: _variant
_variant:
	$(CC) $(VFLAGS) $(COMMON) -c $(SRC) -o $(BUILD)/$(BASE).$(VARIANT).o
	$(LD) -r -T $(SDK)/app.ld $(BUILD)/$(BASE).$(VARIANT).o -o $(BUILD)/$(BASE).$(VARIANT).elf
	@rm -f $(BUILD)/$(BASE).$(VARIANT).o

clean:
	rm -rf $(BUILD)
