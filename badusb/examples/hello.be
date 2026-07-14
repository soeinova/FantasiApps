# BadUSB sample Berry payload - types a greeting over the emulated keyboard.
# Upload to /badusb on the device, then run BadUSB (or set autorun=hello.be).

hid.delay(500)
hid.string('hello from BadUSB via Berry')
hid.key('ENTER')

for i : 1 .. 3
  hid.string('line ' + str(i))
  hid.key('ENTER')
end
