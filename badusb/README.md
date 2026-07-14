# BadUSB - USB HID keyboard (Rubber Ducky-style) app

BadUSB emulates a USB keyboard and runs payloads loaded from LittleFS. The native
payload format is a **Berry script** (`.be`) that drives a small `hid` module;
legacy **Duckyscript** (`.txt`) is also supported, run through a bundled Berry
shim. The interpreter, the US ASCII->HID keycode map, and the `hid` module all
live in the app (`badusb.c`); the firmware only provides raw report delivery and
the keyboard-interface switch, exposed through the app ABI (v2):

- `hid_mode(on)` - bring the keyboard interface up/down (re-enumerates; CDC/MSC
  stay present on the composite targets, so the CLI survives a payload run)
- `hid_send(mods, keys, n)` - send one keyboard report (press or release)
- `hid_host()` - host LED/OS hint bits (for platform detection)

And separately, VFS APIs for script management:

- `list_dir()` / `mkdir()` - used by the script picker + first-run setup

## Berry payloads (`.be`, native)

A payload is a Berry script. The app arms the keyboard, runs the script with a
`hid` module in scope, then disarms - so a payload just calls `hid`:

- `hid.string(s)` - type a string
- `hid.key(k)` - tap one key: a name (`"ENTER"`, `"F4"`, `"UP"`), a single
  character (`"a"`, `"$"`), or a raw HID keycode
- `hid.combo(line)` - a space-separated modifier+key chord
  (`"CTRL ALT DELETE"`, `"GUI r"`, `"ALT F4"`)
- `hid.delay(ms)` - pause between keystrokes
- `hid.host()` - host LED/OS hint bits (for platform detection)

The firmware `hardware` module (buttons/LEDs) is also installed, so payloads can
read buttons or drive LEDs.

Example (`hello.be`, dropped in the payload directory on first run):

```berry
hid.delay(500)
hid.string('hello from BadUSB via Berry')
hid.key('ENTER')
for i : 1 .. 3
  hid.string('line ' + str(i))
  hid.key('ENTER')
end
```

## Launch behavior

1. First run creates `/badusb` and `/badusb/badusb.cfg` (with `autorun=`), plus a
   `hello.be` sample and the Duckyscript shim under `/badusb/duckyscript/`.
2. If the config sets `autorun=<path>`, that script runs immediately - this is
   how the screenless targets (Chameleon Ultra, Proxmark3) choose a payload.
3. Otherwise, on a device with a screen (Flipper/Kiisu) a menu lists both the
   `.be` (Berry) and `.txt` (Duckyscript) payloads in the configured directory
   (`UP`/`DOWN` to move, `OK` to run, `BACK` to exit). Headless with no autorun,
   the list is printed to the CLI.

`/badusb/badusb.cfg`:

```
autorun=            # empty = show the menu; else a script name or /full/path
script_dir=/badusb  # where BadUSB looks for payloads
```

The picker lists both `.be` and `.txt` files, so a traditional Duckyscript can be
launched  from the menu. run_script picks the interpreter by extension: `.txt` goes
to the Duckyscript shim, anything else runs as Berry. A payload can also be run
without the menu by pointing `autorun` at it (`autorun=payload.txt`).

## Duckyscript coverage (1.0 core, legacy)

`.txt` payloads run through `duckyscript.be`, a Berry interpreter the app drops in
`/badusb/duckyscript/` on first run. Supported: `REM`, `DEFAULT_DELAY`, `DELAY`,
`STRING`, `STRINGLN`, `ENTER` and the named keys (`TAB`, `ESC`, `SPACE`,
`DELETE`, `HOME`, `END`, `PAGEUP`/`PAGEDOWN`, arrows, `CAPSLOCK`, `PRINTSCREEN`,
`MENU`, ...), the `CTRL`/`ALT`/`SHIFT`/`GUI` modifiers and combos
(`CTRL ALT DELETE`, `GUI r`, `ALT F4`), `F1`-`F12`, and `REPEAT`. US keyboard
layout.
