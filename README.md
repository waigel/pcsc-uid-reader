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
./pcsc-uid-reader 1          # use the reader with index 1
./pcsc-uid-reader OMNIKEY    # use the first reader whose name contains "OMNIKEY"
```

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

## Scope and limitations

- **UID only.** The tool reads the UID (via `FF CA 00 00 00`), which is enough
  to identify a card. Reading the memory blocks of a MIFARE Classic card would
  additionally require the sector keys and the `FF 86` authenticate + `FF B0`
  read APDUs — not implemented here.
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
