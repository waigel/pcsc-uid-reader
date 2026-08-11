/*
 * pcsc-uid-reader — read the UID, card type and ATR of a contactless
 * RFID/NFC card through a PC/SC reader (e.g. HID OMNIKEY 5022, ACS ACR122U)
 * on macOS.
 *
 * Built on the native winscard API (PCSC.framework).
 * Place a card on the reader and its UID, detected type and ATR are printed.
 *
 * Usage:
 *   pcsc-uid-reader            use the first reader, wait for a card
 *   pcsc-uid-reader -l         list connected readers and exit
 *   pcsc-uid-reader -h         show this help
 *   pcsc-uid-reader 1          use the reader with index 1
 *   pcsc-uid-reader ACR122     use the first reader whose name contains "ACR122"
 */

#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>

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

/* Read the card UID via APDU FF CA 00 00 00. */
static LONG read_uid(SCARDHANDLE card, DWORD protocol,
                     BYTE *uid, DWORD *uid_len) {
    const SCARD_IO_REQUEST *pci =
        (protocol == SCARD_PROTOCOL_T1) ? SCARD_PCI_T1 : SCARD_PCI_T0;

    BYTE get_uid[] = {0xFF, 0xCA, 0x00, 0x00, 0x00};
    BYTE resp[258];
    DWORD resp_len = sizeof(resp);

    LONG rv = SCardTransmit(card, pci, get_uid, sizeof(get_uid),
                            NULL, resp, &resp_len);
    if (rv != SCARD_S_SUCCESS)
        return rv;

    /* The response ends with status word SW1 SW2 = 90 00 on success. */
    if (resp_len < 2 || resp[resp_len - 2] != 0x90 || resp[resp_len - 1] != 0x00)
        return SCARD_F_UNKNOWN_ERROR;

    DWORD n = resp_len - 2;
    if (n > *uid_len)
        n = *uid_len;
    memcpy(uid, resp, n);
    *uid_len = n;
    return SCARD_S_SUCCESS;
}

/* Handle a card once it is present: connect, read ATR + UID, print. */
static void handle_card(SCARDCONTEXT ctx, const char *reader) {
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
    if (rv == SCARD_S_SUCCESS) {
        bytes_to_hex(atr, atr_len, atr_hex, sizeof(atr_hex));
        type = identify_card(atr, atr_len);
    }

    BYTE uid[64];
    DWORD uid_len = sizeof(uid);
    char uid_hex[3 * 64 + 1] = "(not readable — contact card or no UID support)";
    if (read_uid(card, protocol, uid, &uid_len) == SCARD_S_SUCCESS)
        bytes_to_hex(uid, uid_len, uid_hex, sizeof(uid_hex));

    printf("\n=== Card detected ===\n");
    printf("  UID  : %s\n", uid_hex);
    printf("  Type : %s\n", type);
    printf("  ATR  : %s\n", atr_hex);
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

    char *end = NULL;
    long idx = strtol(arg, &end, 10);
    if (*end == '\0')
        return (idx >= 0 && idx < n) ? (int)idx : -1;

    for (int i = 0; i < n; i++)
        if (strstr(names[i], arg))
            return i;
    return -1;
}

static void print_usage(const char *prog) {
    printf("Usage: %s [reader | -l | -h]\n", prog);
    printf("  (no argument)  use the first reader and wait for a card\n");
    printf("  <index>        use the reader with that index\n");
    printf("  <name>         use the first reader whose name contains <name>\n");
    printf("  -l, --list     list connected readers and exit\n");
    printf("  -h, --help     show this help and exit\n");
}

int main(int argc, char **argv) {
    const char *arg = (argc > 1) ? argv[1] : NULL;
    if (arg && (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0)) {
        print_usage(argv[0]);
        return 0;
    }

    /*
     * Install handlers with sigaction() WITHOUT SA_RESTART; see on_signal().
     */
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

    if (arg && (strcmp(arg, "-l") == 0 || strcmp(arg, "--list") == 0)) {
        free(readers_buf);
        SCardReleaseContext(g_ctx);
        return 0;
    }

    int selected = select_reader(arg, names, n);
    if (selected < 0) {
        fprintf(stderr, "no reader matches \"%s\".\n", arg);
        free(readers_buf);
        SCardReleaseContext(g_ctx);
        return 1;
    }

    const char *reader = names[selected];
    printf("\nUsing reader [%d]: %s\n", selected, reader);
    if (n > 1 && !arg)
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
            handle_card(g_ctx, reader);
        }

        rs.dwCurrentState = rs.dwEventState;
    }

    printf("\nBye.\n");
    free(readers_buf);
    SCardReleaseContext(g_ctx);
    return 0;
}
