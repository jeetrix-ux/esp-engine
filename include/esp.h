/* IPsec Encapsulating Security Payload (RFC 4303) with AES-GCM (RFC 4106).
 *
 * Wire format produced by esp_encap():
 *
 *   SPI (4) | Seq low (4) | IV (8) | ciphertext(payload | pad | pad_len | next_hdr) | ICV (16)
 *
 * The engine works on the ESP packet only; the caller adds the outer IP header
 * (or UDP header for NAT-T). In tunnel mode the payload is the whole inner IP
 * packet and next_hdr is 4 (IPv4) or 41 (IPv6). */
#ifndef ESP_H
#define ESP_H

#include "gcm.h"
#include "replay.h"

#include <stddef.h>
#include <stdint.h>

#define ESP_HDR_LEN 8
#define ESP_IV_LEN 8
#define ESP_ICV_LEN 16
#define ESP_SALT_LEN 4
/* worst-case growth: header + IV + 3 pad + pad_len + next_hdr + ICV */
#define ESP_OVERHEAD (ESP_HDR_LEN + ESP_IV_LEN + 3 + 2 + ESP_ICV_LEN)

enum esp_err {
    ESP_OK = 0,
    ESP_ERR_PARAM = -1,
    ESP_ERR_SPACE = -2,        /* output buffer too small */
    ESP_ERR_SEQ_OVERFLOW = -3, /* sequence space exhausted: SA must be rekeyed */
    ESP_ERR_TRUNCATED = -4,    /* shorter than the smallest valid ESP packet */
    ESP_ERR_SPI = -5,          /* SPI does not belong to this SA */
    ESP_ERR_REPLAY = -6,       /* duplicate sequence number */
    ESP_ERR_STALE = -7,        /* sequence number left of the replay window */
    ESP_ERR_AUTH = -8,         /* ICV check failed */
    ESP_ERR_PADDING = -9,      /* bad pad length or pad contents */
};

typedef struct {
    uint64_t packets, bytes;
    uint64_t err_auth, err_replay, err_stale, err_padding, err_other;
} esp_stats;

typedef struct {
    uint32_t spi;
    uint8_t salt[ESP_SALT_LEN];
    gcm_ctx gcm;
    int esn;                /* 64-bit extended sequence numbers (RFC 4303 2.2.1) */
    int check_padding;      /* verify pad bytes are 1, 2, 3, ... (RFC 4303 2.4) */
    uint64_t seq;           /* outbound: last sequence number sent */
    replay_window replay;   /* inbound */
    esp_stats stats;
} esp_sa;

typedef struct {
    uint32_t spi;
    const uint8_t *key;     /* AES key followed by the 4-byte salt (RFC 4106 KEYMAT) */
    size_t key_len;         /* 20, 28 or 36 */
    int esn;
    uint32_t replay_window; /* 0 selects 64 */
    enum aes_impl aes;
    enum ghash_impl ghash;
} esp_sa_config;

int esp_sa_init(esp_sa *sa, const esp_sa_config *cfg);

/* Encrypt `payload` into `out`. Returns the ESP packet length or a negative esp_err. */
int esp_encap(esp_sa *sa, const uint8_t *payload, size_t len, uint8_t next_hdr,
              uint8_t *out, size_t out_cap);

/* Authenticate and decrypt the ESP packet `pkt`. On success writes the inner
 * payload to `out`, sets *next_hdr, and returns the payload length. */
int esp_decap(esp_sa *sa, const uint8_t *pkt, size_t len,
              uint8_t *out, size_t out_cap, uint8_t *next_hdr);

const char *esp_strerror(int err);

#endif
