/* libFuzzer harness for the inbound path, built with ASan + UBSan.
 *
 * The first input byte picks a mode:
 *   0: raw bytes straight into esp_decap (pre-authentication parsing: lengths,
 *      SPI, sequence/ESN inference, replay window), the code an attacker can
 *      reach without the key;
 *   1: round trip, where any payload must come back unchanged through encap/decap;
 *   2: the fuzzer's bytes become the decrypted trailer of a packet with a valid
 *      ICV, which reaches the padding/next-header parsing behind the ICV check.
 *
 *   clang -g -O1 -fsanitize=fuzzer,address,undefined -Iinclude tests/fuzz_decap.c src/[a-f]*.c src/replay.c
 */
#include "esp.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t keymat[20] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0xa, 0xb, 0xc, 0xd};
#define SPI 0x1234u

static void sa_init(esp_sa *sa, int esn)
{
    esp_sa_config cfg = {.spi = SPI, .key = keymat, .key_len = sizeof keymat, .esn = esn,
                         .replay_window = 128, .aes = AES_IMPL_TABLE, .ghash = GHASH_IMPL_TABLE};
    if (esp_sa_init(sa, &cfg) != ESP_OK)
        abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static uint8_t out[70000], pkt[70000];
    uint8_t nh;
    if (size < 2)
        return 0;
    int mode = data[0] % 3, esn = data[1] & 1;
    data += 2;
    size -= 2;

    esp_sa rx;
    sa_init(&rx, esn);

    if (mode == 0) {
        /* also exercise the replay window by feeding the same bytes repeatedly */
        for (int i = 0; i < 3; i++)
            esp_decap(&rx, data, size, out, sizeof out, &nh);
        return 0;
    }

    if (mode == 1) {
        esp_sa tx;
        sa_init(&tx, esn);
        int n = esp_encap(&tx, data, size, 4, pkt, sizeof pkt);
        if (n < 0)
            abort();
        int m = esp_decap(&rx, pkt, (size_t)n, out, sizeof out, &nh);
        if (m != (int)size || nh != 4 || memcmp(out, data, size) != 0)
            abort(); /* round-trip property violated */
        if (esp_decap(&rx, pkt, (size_t)n, out, sizeof out, &nh) != ESP_ERR_REPLAY)
            abort(); /* the second copy must be caught as a replay */
        return 0;
    }

    /* mode 2: authenticate an arbitrary plaintext trailer */
    if (size > sizeof pkt - 32)
        return 0;
    uint8_t hdr[8] = {0, 0, SPI >> 8, SPI & 0xff, 0, 0, 0, 1};
    uint8_t nonce[12] = {0xa, 0xb, 0xc, 0xd, 0, 0, 0, 0, 0, 0, 0, 1};
    uint8_t aad[12] = {0, 0, SPI >> 8, SPI & 0xff, 0, 0, 0, 0, 0, 0, 0, 1};
    memcpy(pkt, hdr, 8);
    memcpy(pkt + 8, nonce + 4, 8);
    if (esn)
        gcm_seal(&rx.gcm, nonce, aad, 12, data, size, pkt + 16, pkt + 16 + size);
    else
        gcm_seal(&rx.gcm, nonce, hdr, 8, data, size, pkt + 16, pkt + 16 + size);
    int m = esp_decap(&rx, pkt, 16 + size + 16, out, sizeof out, &nh);
    if (m >= 0 && (size_t)m + 2 > size)
        abort(); /* payload cannot be longer than the plaintext minus its trailer */
    return 0;
}
