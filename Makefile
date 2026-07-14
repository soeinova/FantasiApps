# Build a Fantasi app from this repo into loadable ELF(s):  make app APP=hello
#
# Apps live at the repo root as <app>/<app>.c with metadata in <app>/app.json.
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
COMMON := -Os -ffreestanding -fno-common -mword-relocations -mlong-calls \
          -ffunction-sections -fdata-sections -nostdlib -Wall -I$(SDK) \
          -I$(BERRY) -I$(BERRY)/src

# Per-core flags. Cortex-M is Thumb-2 + hard FP; ARM7TDMI is ARM-mode + interwork.
CM4_FLAGS  := -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16
ARM7_FLAGS := -mcpu=arm7tdmi -mthumb-interwork

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
	$(MAKE) --no-print-directory _variant APP=$(APP) NAME="$$name" VARIANT=cm4  VFLAGS="$(CM4_FLAGS)" && \
	$(MAKE) --no-print-directory _variant APP=$(APP) NAME="$$name" VARIANT=arm7 VFLAGS="$(ARM7_FLAGS)" && \
	echo "built $(BUILD)/$$name.cm4.elf (FZ/CU) and $(BUILD)/$$name.arm7.elf (PM3)"

# Internal: build one architecture variant.
.PHONY: _variant
_variant:
	$(CC) $(VFLAGS) $(COMMON) -c $(APP)/$(APP).c -o $(BUILD)/$(NAME).$(VARIANT).o
	$(LD) -r -T $(SDK)/app.ld $(BUILD)/$(NAME).$(VARIANT).o -o $(BUILD)/$(NAME).$(VARIANT).elf
	@rm -f $(BUILD)/$(NAME).$(VARIANT).o

clean:
	rm -rf $(BUILD)
