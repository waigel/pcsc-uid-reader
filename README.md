# pcsc-uid-reader

A small C command-line tool for macOS that reads the **UID**, **card type** and
**ATR** of a contactless RFID/NFC card through any PC/SC reader (e.g. HID
OMNIKEY 5022, ACS ACR122U). It uses the native PC/SC interface
(`PCSC.framework`), so no third-party driver is required.

## Requirements

- macOS with Xcode Command Line Tools (`cc`, `make`)
- A PC/SC (CCID) contactless reader
- `PCSC.framework` — already part of macOS

## Build

```bash
make
```

This produces the `pcsc-uid-reader` binary.

## Usage

```bash
./pcsc-uid-reader            # use the first reader, wait for a card
./pcsc-uid-reader -l         # list connected readers and exit
./pcsc-uid-reader -h         # show help
./pcsc-uid-reader -d         # also dump MIFARE Classic sectors (default keys)
./pcsc-uid-reader -j         # emit JSON on stdout (one object per card)
./pcsc-uid-reader 1          # use the reader with index 1
./pcsc-uid-reader OMNIKEY    # use the first reader whose name contains "OMNIKEY"
```

Flags and the reader selector can be combined, e.g. `./pcsc-uid-reader -d OMNIKEY`.

With `-j`, stdout carries one JSON object per detected card (status text goes to
stderr), so it pipes cleanly into tools like `jq`:

```bash
./pcsc-uid-reader -j OMNIKEY | jq '{uid, type}'
```

Shape: `{"reader","uid","type","atr"}`, plus `"dump":{"sectors":[…],"blocks_read"}`
when dumping. Each sector is either `{"sector","locked":true}` or
`{"sector","locked":false,"key","key_type","blocks":[…]}`.

Place a card on the reader — its UID, type and ATR are printed. Press `Ctrl-C`
to quit.

Example output:

```
Readers found (1):
  [0] ACS ACR122U PICC Interface

Using reader [0]: ACS ACR122U PICC Interface
Place a card on the reader … (Ctrl-C to quit)

=== Card detected ===
  UID  : 04 A2 3F 1B 6C 80
  Type : MIFARE Ultralight
  ATR  : 3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 03 00 00 00 00 68
```

## How it works

- `SCardEstablishContext` / `SCardListReaders` — connect to PC/SC and enumerate
  readers.
- `SCardGetStatusChange` — block until a card enters the field.
- `SCardStatus` — obtain the ATR; the card type is derived from the ATR's
  historical bytes (the standard PC/SC contactless ATR encodes the card name).
- APDU `FF CA 00 00 00` via `SCardTransmit` — read the UID.

## Dumping MIFARE Classic sectors (`-d`)

With `-d`, once a MIFARE Classic card is detected the tool tries a small
dictionary of **factory-default keys** against every sector (`FF 82` load key,
`FF 86` authenticate, `FF B0` read binary) and prints the blocks it can read as
hex and ASCII. Sectors protected with non-default keys are reported as locked.

```
--- MIFARE Classic memory dump (default keys only) ---
  sector  0 : key A = FF FF FF FF FF FF
    block  0 : DE AD BE EF 00 08 04 00 62 63 64 65 66 67 68 69  |........bcdefghi|
    block  1 : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
    block  2 : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
    block  3 : 00 00 00 00 00 00 FF 07 80 69 FF FF FF FF FF FF  |.........i......|
  sector  4 : no default key worked (locked)
  ...
```

It uses **only well-known default keys** — no CRYPTO1 key-recovery attack is
implemented. Sectors with custom keys require dedicated hardware/tooling (e.g.
a Proxmark3 or Flipper Zero) that is out of scope here. Intended for inspecting
your own cards.

### Supplying your own keys (`-k`)

If you already know the keys for the protected sectors (recovered elsewhere),
pass them in a key file so the tool can read those sectors too:

```bash
./pcsc-uid-reader -k mykeys.txt OMNIKEY
```

The file lists one key per line as 12 hex digits (spaces optional, `#` starts a
comment); see [keys.example.txt](keys.example.txt). Your keys are tried before
the built-in defaults. `-k` implies `-d`. Keep real key files out of version
control — they are secrets.

## Scope and limitations

- **UID and default-key sectors.** The tool reads the UID (via `FF CA 00 00 00`)
  and, with `-d`, any MIFARE Classic sectors still protected by factory-default
  keys. Sectors with custom keys are not accessible.
- **Contactless PC/SC readers.** A contact-only reader cannot read contactless
  cards. Cheap "keyboard-wedge" readers that type the UID as text do not appear
  in PC/SC and are not supported by this tool.
- **USB docks/hubs** occasionally fail to pass a reader through to macOS. If
  `-l` does not list your reader, connect it directly to the machine.

## Troubleshooting

Run `./pcsc-uid-reader -l` to see what macOS currently detects. If your reader
is not listed, the operating system does not see it and no program can read from
it — check the cable (some are power-only), try a different USB port, and avoid
docks/hubs that may not pass the reader through.

## Security note

The card UID is **not a secret** — it is transmitted in the clear during
anti-collision and can be cloned. MIFARE Classic's CRYPTO1 cipher has been
broken since ~2008, so UID-based access control offers no real security. This
tool is intended for inspecting your own cards and for learning purposes.

## License

MIT — see [LICENSE](LICENSE).
