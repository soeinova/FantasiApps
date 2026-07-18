# BadUSB payload: draw "fantasi" into Notepad on Windows using Alt codes and block characters.

hid.delay(600)
hid.combo('GUI r') # Win+R -> Run
hid.delay(400)
hid.string('notepad')
hid.key('ENTER')
hid.delay(1000)

var art = [
  "",
  "         TBTBTBFFFFFFFF                                    BFFFFF",
  "       TBTBTBFFFFFFFTTT                                    FFFFFF                                       FFFFFFF",
  "      T F F FFFFFFFT                                       FFFFFF                                       FFFFFFT",
  "      T T T FFFFFF                                         FFFFFF                                       TTTTTT",
  "B B B BBBBBFFFFFFFBBBB   BBBBBBBBBBB   BBBBB  BBBBBBB   BBBFFFFFFBBBB   BBBBBBBBBBBB     BBBBBBBBBBBBB  BBBBBB",
  "B F F FFFFFFFFFFFFFFFF  FFFFFFFFFFFFF  FFFFFBFFFFFFFFB  FFFFFFFFFFFFF   FFFFFFFFFFFFF   FFFFFFFFFFFFFF  FFFFFFF",
  "B F F FFFFFFFFFFFFFFFF         FFFFFF  FFFFFFFFFFFFFFF  TTTFFFFFFTTTT          FFFFFF  FFFFFFF          FFFFFFF",
  "      B B B FFFFFF             FFFFFF  FFFFFFT  FFFFFF     FFFFFF              FFFFFF  FFFFFFFBBBB      FFFFFFF",
  "      B F F FFFFFF    BBFFFFFFFFFFFFF  FFFFFF   FFFFFF     FFFFFF     BFFFFFFFFFFFFFF  FFFFFFFFFFFFFB   FFFFFFF",
  "      B F F FFFFFF   FFFFFFT   FFFFFF  FFFFFF   FFFFFF     FFFFFF   BFFFFFFT   FFFFFF   TTFFFFFFFFFFFF  FFFFFFF",
  "      B F F FFFFFF   FFFFFF    FFFFFF  FFFFFF   FFFFFF     FFFFFF   FFFFFFF    FFFFFF           FFFFFF  FFFFFFF",
  "      B F F FFFFFF   FFFFFFB BFFFFFFF  FFFFFF   FFFFFF     FFFFFFB  FFFFFFB  BFFFFFFF          BFFFFFF  FFFFFFF",
  "      B F F FFFFFF   FFFFFFFFF FFFFFF  FFFFFF   FFFFFF     FFFFFFFB TFFFFFFFFF FFFFFF  FFFFFFFFFFFFFFT  FFFFFFF",
  "      B F F FFFFFT    TFFFFFT  FFFFFF  FFFFFF   FFFFFF      TFFFFFF   TFFFFFT  FFFFFF  TFFFFFFFFFFFT    TFFFFFT",
  "      B F F FFFT",
  "      B F F FT",
]

def draw(row)
  for i : 0 .. size(row) - 1
    var c = row[i]
    if c == ' '
      hid.string(' ')
    elif c == 'F'
      hid.altcode(219)
    elif c == 'B'
      hid.altcode(220)
    elif c == 'T'
      hid.altcode(223)
    end
  end
end

for row : art
  draw(row)
  hid.key('ENTER')
end
