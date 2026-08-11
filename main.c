/*
 * pcsc-uid-reader — read the UID, card type and ATR of a contactless
 * RFID/NFC card through a PC/SC reader (e.g. HID OMNIKEY 5022, ACS ACR122U)
 * on macOS.
 *
 * Built on the native winscard API (PCSC.framework).
 * Place a card on the reader and its UID, detected type and ATR are printed.
 * With --dump, MIFARE Classic sectors are read using a dictionary of default
 * keys (CRYPTO1 authentication via the standard PC/SC pseudo-APDUs).
 *
 * Usage:
 *   pcsc-uid-reader            use the first reader, wait for a card
 *   pcsc-uid-reader -l         list connected readers and exit
 *   pcsc-uid-reader -h         show this help
 *   pcsc-uid-reader -d         also dump MIFARE Classic sectors (default keys)
 *   pcsc-uid-reader 1          use the reader with index 1
 *   pcsc-uid-reader ACR122     use the first reader whose name contains "ACR122"
 *
 * The dump feature uses only well-known factory-default keys; it does not
 * implement any CRYPTO1 key-recovery attack. Intended for inspecting your own
 * cards and for learning purposes.
 */

#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>

#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Global context so the signal handler can call SCardCancel(). */
static SCARDCONTEXT g_ctx = 0;
static volatile sig_atomic_t g_running = 1;

/*
 * SIGINT/SIGTERM: clear the loop flag AND unblock the pending
 * SCardGetStatusChange via SCardCancel. On macOS the status-change call
 * neither honours its timeout reliably nor gets interrupted by a plain
 * signal() handler, so without the cancel the program would hang on Ctrl-C.
 * The handler is installed with sigaction() WITHOUT SA_RESTART so the call
 * returns SCARD_E_CANCELLED instead of being restarted.
 */
static void on_signal(int sig) {
    (void)sig;
    g_running = 0;
    if (g_ctx)
        SCardCancel(g_ctx);
}

/* Well-known factory-default MIFARE Classic keys (6 bytes each). */
static const BYTE DEFAULT_KEYS[][6] = {
    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
    {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5},
    {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0},
    {0xA1, 0xB1, 0xC1, 0xD1, 0xE1, 0xF1},
    {0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5},
    {0x4D, 0x3A, 0x99, 0xC3, 0x51, 0xDD},
    {0x1A, 0x98, 0x2C, 0x7E, 0x45, 0x9A},
    {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
    {0x71, 0x4C, 0x5C, 0x88, 0x6E, 0x97},
    {0x58, 0x7E, 0xE5, 0xF9, 0x35, 0x0F},
    {0xA0, 0x47, 0x8C, 0xC3, 0x90, 0x91},
    {0x53, 0x3C, 0xB6, 0xC7, 0x23, 0xF6},
    {0x8F, 0xD0, 0xA4, 0xF2, 0x56, 0xE9},
};
#define NUM_DEFAULT_KEYS (sizeof(DEFAULT_KEYS) / sizeof(DEFAULT_KEYS[0]))

/* Extra keys loaded at runtime via --keys <file>, tried before the defaults. */
#define MAX_USER_KEYS 256
static BYTE g_user_keys[MAX_USER_KEYS][6];
static int g_num_user_keys = 0;

/*
 * Load candidate keys from a text file: one key per line as 12 hex digits,
 * spaces optional ("A0B0C0D0E0F0" or "A0 B0 C0 D0 E0 F0"); '#' starts a
 * comment. Returns the number of keys loaded, or -1 if the file can't be read.
 */
static int load_keys_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    char line[256];
    while (fgets(line, sizeof(line), f) && g_num_user_keys < MAX_USER_KEYS) {
        char hex[16];
        int h = 0;
        for (char *p = line; *p && h < (int)sizeof(hex) - 1; p++) {
            if (*p == '#')
                break;
            if (isxdigit((unsigned char)*p))
                hex[h++] = *p;
        }
        hex[h] = '\0';
        if (h != 12)
            continue; /* need exactly 6 bytes */

        for (int i = 0; i < 6; i++) {
            unsigned int v;
            sscanf(hex + i * 2, "%2x", &v);
            g_user_keys[g_num_user_keys][i] = (BYTE)v;
        }
        g_num_user_keys++;
    }
    fclose(f);
    return g_num_user_keys;
}

/* Format a byte buffer as a hex string, e.g. "04 A2 3F". */
static void bytes_to_hex(const BYTE *buf, DWORD len, char *out, size_t out_size) {
    size_t pos = 0;
    for (DWORD i = 0; i < len && pos + 3 < out_size; i++) {
        pos += (size_t)snprintf(out + pos, out_size - pos, "%02X%s",
                                buf[i], (i + 1 < len) ? " " : "");
    }
    if (out_size > 0)
        out[pos < out_size ? pos : out_size - 1] = '\0';
}

/*
 * Identify the card type from the ATR (standard PC/SC ATR for contactless
 * cards): 3B 8F 80 01 <RID: A0 00 00 03 06> <SS> <name: NN NN> ... <TCK>
 * where SS is the standard (03 = ISO14443A) and NN NN is the card name.
 */
static const char *identify_card(const BYTE *atr, DWORD atr_len) {
    static const BYTE pcsc_rid[] = {0xA0, 0x00, 0x00, 0x03, 0x06};

    if (atr_len < 15)
        return "unknown (ATR too short / contact card?)";

    DWORD idx = 0;
    int found = 0;
    for (DWORD i = 0; i + sizeof(pcsc_rid) + 3 <= atr_len; i++) {
        if (memcmp(atr + i, pcsc_rid, sizeof(pcsc_rid)) == 0) {
            idx = i + (DWORD)sizeof(pcsc_rid);
            found = 1;
            break;
        }
    }
    if (!found)
        return "unknown (not a PC/SC contactless ATR)";

    if (idx + 3 > atr_len)
        return "unknown";

    BYTE ss = atr[idx];
    unsigned name = ((unsigned)atr[idx + 1] << 8) | atr[idx + 2];

    switch (name) {
        case 0x0001: return "MIFARE Classic 1K";
        case 0x0002: return "MIFARE Classic 4K";
        case 0x0003: return "MIFARE Ultralight";
        case 0x0026: return "MIFARE Mini";
        case 0x003A: return "MIFARE Ultralight C";
        case 0x0036: return "MIFARE Plus SL1 2K";
        case 0x0037: return "MIFARE Plus SL1 4K";
        case 0x0038: return "MIFARE Plus SL2 2K";
        case 0x0039: return "MIFARE Plus SL2 4K";
        case 0xFF88: return "MIFARE DESFire (likely)";
        case 0xF004: return "Topaz/Jewel";
        case 0xF011: return "FeliCa 212k";
        case 0xF012: return "FeliCa 424k";
        default: break;
    }

    if (ss == 0x11)
        return "ISO14443-4 card (likely DESFire)";

    return "unknown (see ATR name bytes)";
}

/* True if the ATR identifies a MIFARE Classic 1K or 4K card. */
static int is_mifare_classic(const BYTE *atr, DWORD atr_len) {
    const char *t = identify_card(atr, atr_len);
    return strncmp(t, "MIFARE Classic", 14) == 0;
}

/* Select the IO request block for the active protocol. */
static const SCARD_IO_REQUEST *pci_for(DWORD protocol) {
    return (protocol == SCARD_PROTOCOL_T1) ? SCARD_PCI_T1 : SCARD_PCI_T0;
}

/*
 * Send an APDU and return 1 if the response status word is 90 00.
 * The response payload (without SW) is copied to out/out_len when provided.
 */
static int send_apdu(SCARDHANDLE card, DWORD protocol,
                     const BYTE *apdu, DWORD apdu_len,
                     BYTE *out, DWORD *out_len) {
    BYTE resp[258];
    DWORD resp_len = sizeof(resp);
    LONG rv = SCardTransmit(card, pci_for(protocol), apdu, apdu_len,
                            NULL, resp, &resp_len);
    if (rv != SCARD_S_SUCCESS || resp_len < 2)
        return 0;
    if (resp[resp_len - 2] != 0x90 || resp[resp_len - 1] != 0x00)
        return 0;

    if (out && out_len) {
        DWORD n = resp_len - 2;
        if (n > *out_len)
            n = *out_len;
        memcpy(out, resp, n);
        *out_len = n;
    }
    return 1;
}

/* Read the card UID via APDU FF CA 00 00 00. */
static int read_uid(SCARDHANDLE card, DWORD protocol, BYTE *uid, DWORD *uid_len) {
    BYTE get_uid[] = {0xFF, 0xCA, 0x00, 0x00, 0x00};
    return send_apdu(card, protocol, get_uid, sizeof(get_uid), uid, uid_len);
}

/*
 * Load a 6-byte key into the reader's key slot 0 (FF 82).
 * Readers disagree on the key structure byte (P1): the ACS ACR122U wants
 * 0x00 (volatile) while the HID OMNIKEY 5022 requires 0x20 (non-volatile),
 * so try volatile first and fall back to non-volatile.
 */
static int load_key(SCARDHANDLE card, DWORD protocol, const BYTE *key) {
    BYTE apdu[11] = {0xFF, 0x82, 0x00, 0x00, 0x06};
    memcpy(apdu + 5, key, 6);
    if (send_apdu(card, protocol, apdu, sizeof(apdu), NULL, NULL))
        return 1;
    apdu[2] = 0x20; /* non-volatile key location */
    return send_apdu(card, protocol, apdu, sizeof(apdu), NULL, NULL);
}

/* Authenticate a block with the loaded key (FF 86). key_type: 0x60=A, 0x61=B. */
static int authenticate(SCARDHANDLE card, DWORD protocol, BYTE block, BYTE key_type) {
    BYTE apdu[] = {0xFF, 0x86, 0x00, 0x00, 0x05,
                   0x01, 0x00, block, key_type, 0x00};
    return send_apdu(card, protocol, apdu, sizeof(apdu), NULL, NULL);
}

/* Read 16 bytes from a block (FF B0). */
static int read_block(SCARDHANDLE card, DWORD protocol, BYTE block, BYTE *out16) {
    BYTE apdu[] = {0xFF, 0xB0, 0x00, block, 0x10};
    DWORD len = 16;
    return send_apdu(card, protocol, apdu, sizeof(apdu), out16, &len) && len == 16;
}

/*
 * Try a list of keys (Key A then Key B) against a block. On success returns 1
 * and reports the key type ('A'/'B') and a pointer to the matching key.
 */
static int try_key_list(SCARDHANDLE card, DWORD protocol, BYTE block,
                        const BYTE keys[][6], int count,
                        char *key_type_out, const BYTE **key_out) {
    for (int k = 0; k < count; k++) {
        if (!load_key(card, protocol, keys[k]))
            continue;
        if (authenticate(card, protocol, block, 0x60)) {
            *key_type_out = 'A';
            *key_out = keys[k];
            return 1;
        }
        if (authenticate(card, protocol, block, 0x61)) {
            *key_type_out = 'B';
            *key_out = keys[k];
            return 1;
        }
    }
    return 0;
}

/*
 * Find a working key for the sector's first block: user-provided keys first,
 * then the factory defaults. Reports the key type and the matching key bytes.
 */
static int find_sector_key(SCARDHANDLE card, DWORD protocol, BYTE first_block,
                           char *key_type_out, const BYTE **key_out) {
    if (try_key_list(card, protocol, first_block, g_user_keys, g_num_user_keys,
                     key_type_out, key_out))
        return 1;
    return try_key_list(card, protocol, first_block, DEFAULT_KEYS,
                        (int)NUM_DEFAULT_KEYS, key_type_out, key_out);
}

/* Print one block as hex plus a printable-ASCII rendering. */
static void print_block(BYTE block, const BYTE *data) {
    char hex[3 * 16 + 1];
    bytes_to_hex(data, 16, hex, sizeof(hex));
    char ascii[17];
    for (int i = 0; i < 16; i++)
        ascii[i] = isprint(data[i]) ? (char)data[i] : '.';
    ascii[16] = '\0';
    printf("    block %2u : %s  |%s|\n", block, hex, ascii);
}

/*
 * Dump all 16 sectors of a MIFARE Classic 1K, trying default keys per sector.
 * Blocks that authenticate are read and printed; the rest are reported as
 * locked with an unknown key.
 */
static void dump_mifare_classic(SCARDHANDLE card, DWORD protocol) {
    printf("\n--- MIFARE Classic memory dump (default keys only) ---\n");
    int readable = 0;
    for (BYTE sector = 0; sector < 16; sector++) {
        BYTE first = (BYTE)(sector * 4);
        char kt = '?';
        const BYTE *key = NULL;

        if (!find_sector_key(card, protocol, first, &kt, &key)) {
            printf("  sector %2u : no known key worked (locked)\n", sector);
            continue;
        }

        char key_hex[3 * 6 + 1];
        bytes_to_hex(key, 6, key_hex, sizeof(key_hex));
        printf("  sector %2u : key %c = %s\n", sector, kt, key_hex);

        for (BYTE b = first; b < first + 4; b++) {
            BYTE data[16];
            /* Re-authenticate per block; some readers require it. */
            authenticate(card, protocol, b, kt == 'A' ? 0x60 : 0x61);
            if (read_block(card, protocol, b, data)) {
                print_block(b, data);
                readable++;
            } else {
                printf("    block %2u : (read failed)\n", b);
            }
        }
    }
    printf("--- %d of 64 blocks read ---\n", readable);
}

/* Handle a card once it is present: connect, read ATR + UID, optionally dump. */
static void handle_card(SCARDCONTEXT ctx, const char *reader, int want_dump) {
    SCARDHANDLE card;
    DWORD protocol = 0;

    LONG rv = SCardConnect(ctx, reader, SCARD_SHARE_SHARED,
                           SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                           &card, &protocol);
    if (rv != SCARD_S_SUCCESS) {
        fprintf(stderr, "  connect failed: %s\n", pcsc_stringify_error(rv));
        return;
    }

    BYTE atr[MAX_ATR_SIZE];
    DWORD atr_len = sizeof(atr);
    DWORD state = 0, active_proto = 0;
    char reader_name[256];
    DWORD reader_name_len = sizeof(reader_name);

    rv = SCardStatus(card, reader_name, &reader_name_len,
                     &state, &active_proto, atr, &atr_len);

    char atr_hex[3 * MAX_ATR_SIZE + 1] = "(unavailable)";
    const char *type = "unknown";
    int classic = 0;
    if (rv == SCARD_S_SUCCESS) {
        bytes_to_hex(atr, atr_len, atr_hex, sizeof(atr_hex));
        type = identify_card(atr, atr_len);
        classic = is_mifare_classic(atr, atr_len);
    }

    BYTE uid[64];
    DWORD uid_len = sizeof(uid);
    char uid_hex[3 * 64 + 1] = "(not readable — contact card or no UID support)";
    if (read_uid(card, protocol, uid, &uid_len))
        bytes_to_hex(uid, uid_len, uid_hex, sizeof(uid_hex));

    printf("\n=== Card detected ===\n");
    printf("  UID  : %s\n", uid_hex);
    printf("  Type : %s\n", type);
    printf("  ATR  : %s\n", atr_hex);

    if (want_dump) {
        if (classic)
            dump_mifare_classic(card, protocol);
        else
            printf("  (dump: only MIFARE Classic is supported)\n");
    }
    fflush(stdout);

    SCardDisconnect(card, SCARD_LEAVE_CARD);
}

/*
 * Read the multi-string reader list into an array of pointers.
 * Returns the count; the caller must free *buf. The names[] entries
 * point into *buf (do not free them individually).
 */
static int list_readers(SCARDCONTEXT ctx, char **buf, const char *names[], int max) {
    DWORD len = 0;
    if (SCardListReaders(ctx, NULL, NULL, &len) != SCARD_S_SUCCESS || len == 0)
        return 0;

    *buf = malloc(len);
    if (!*buf)
        return 0;

    if (SCardListReaders(ctx, NULL, *buf, &len) != SCARD_S_SUCCESS) {
        free(*buf);
        *buf = NULL;
        return 0;
    }

    int count = 0;
    for (const char *p = *buf; *p && count < max; p += strlen(p) + 1)
        names[count++] = p;
    return count;
}

/*
 * Resolve the reader-selection argument to an index into names[].
 * A pure number selects by index; anything else matches a name substring.
 * Returns the index, or -1 if no reader matches.
 */
static int select_reader(const char *arg, const char *names[], int n) {
    if (!arg)
        return 0;

    /* A pure, in-range number selects by index; otherwise fall back to a
     * name substring match (so "5022" matches a reader named "… 5022 …"). */
    char *end = NULL;
    long idx = strtol(arg, &end, 10);
    if (*end == '\0' && idx >= 0 && idx < n)
        return (int)idx;

    for (int i = 0; i < n; i++)
        if (strstr(names[i], arg))
            return i;
    return -1;
}

static void print_usage(const char *prog) {
    printf("Usage: %s [reader] [-d] [-k <file>] [-l] [-h]\n", prog);
    printf("  (no argument)  use the first reader and wait for a card\n");
    printf("  <index>        use the reader with that index\n");
    printf("  <name>         use the first reader whose name contains <name>\n");
    printf("  -d, --dump     also dump MIFARE Classic sectors (default keys)\n");
    printf("  -k, --keys <f> add extra MIFARE keys from file <f> (implies -d)\n");
    printf("  -l, --list     list connected readers and exit\n");
    printf("  -h, --help     show this help and exit\n");
}

int main(int argc, char **argv) {
    int want_dump = 0, want_list = 0;
    const char *selector = NULL;
    const char *keys_path = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(a, "-d") == 0 || strcmp(a, "--dump") == 0) {
            want_dump = 1;
        } else if (strcmp(a, "-k") == 0 || strcmp(a, "--keys") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "%s requires a file argument\n", a);
                return 1;
            }
            keys_path = argv[++i];
            want_dump = 1; /* providing keys implies a dump */
        } else if (strcmp(a, "-l") == 0 || strcmp(a, "--list") == 0) {
            want_list = 1;
        } else if (!selector) {
            selector = a;
        }
    }

    if (keys_path) {
        int loaded = load_keys_file(keys_path);
        if (loaded < 0) {
            fprintf(stderr, "could not read keys file: %s\n", keys_path);
            return 1;
        }
        printf("Loaded %d extra key(s) from %s\n", loaded, keys_path);
    }

    /* Install handlers with sigaction() WITHOUT SA_RESTART; see on_signal(). */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    LONG rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &g_ctx);
    if (rv != SCARD_S_SUCCESS) {
        fprintf(stderr, "failed to establish PC/SC context: %s\n",
                pcsc_stringify_error(rv));
        return 1;
    }

    char *readers_buf = NULL;
    const char *names[32];
    int n = list_readers(g_ctx, &readers_buf, names, 32);
    if (n == 0) {
        fprintf(stderr, "no PC/SC reader found. Is the reader plugged in?\n");
        SCardReleaseContext(g_ctx);
        return 1;
    }

    printf("Readers found (%d):\n", n);
    for (int i = 0; i < n; i++)
        printf("  [%d] %s\n", i, names[i]);

    if (want_list) {
        free(readers_buf);
        SCardReleaseContext(g_ctx);
        return 0;
    }

    int selected = select_reader(selector, names, n);
    if (selected < 0) {
        fprintf(stderr, "no reader matches \"%s\".\n", selector);
        free(readers_buf);
        SCardReleaseContext(g_ctx);
        return 1;
    }

    const char *reader = names[selected];
    printf("\nUsing reader [%d]: %s\n", selected, reader);
    if (n > 1 && !selector)
        printf("(select another with: %s <index> or %s <name>)\n",
               argv[0], argv[0]);
    printf("Place a card on the reader … (Ctrl-C to quit)\n");
    fflush(stdout);

    SCARD_READERSTATE rs;
    memset(&rs, 0, sizeof(rs));
    rs.szReader = reader;
    rs.dwCurrentState = SCARD_STATE_UNAWARE;

    while (g_running) {
        rv = SCardGetStatusChange(g_ctx, INFINITE, &rs, 1);

        if (rv == (LONG)SCARD_E_CANCELLED)
            break; /* triggered by Ctrl-C */

        if (rv != SCARD_S_SUCCESS) {
            fprintf(stderr, "status change failed: %s\n", pcsc_stringify_error(rv));
            break;
        }

        /* Card newly present (rising edge only). */
        if ((rs.dwEventState & SCARD_STATE_PRESENT) &&
            !(rs.dwCurrentState & SCARD_STATE_PRESENT)) {
            handle_card(g_ctx, reader, want_dump);
        }

        rs.dwCurrentState = rs.dwEventState;
    }

    printf("\nBye.\n");
    free(readers_buf);
    SCardReleaseContext(g_ctx);
    return 0;
}
