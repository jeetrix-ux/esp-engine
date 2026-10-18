#include "esp.h"

#include <string.h>

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t get_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

int esp_sa_init(esp_sa *sa, const esp_sa_config *cfg)
{
    if (!cfg->key || cfg->key_len <= ESP_SALT_LEN || cfg->spi < 256)
        return ESP_ERR_PARAM; /* SPIs 1-255 are reserved by IANA, 0 is never valid */
    memset(sa, 0, sizeof *sa);
    size_t aes_len = cfg->key_len - ESP_SALT_LEN;
    if (gcm_init(&sa->gcm, cfg->key, aes_len, cfg->aes, cfg->ghash) != GCM_OK)
        return ESP_ERR_PARAM;
    if (replay_init(&sa->replay, cfg->replay_window ? cfg->replay_window : 64) != 0)
        return ESP_ERR_PARAM;
    memcpy(sa->salt, cfg->key + aes_len, ESP_SALT_LEN);
    sa->spi = cfg->spi;
    sa->esn = cfg->esn;
    sa->check_padding = 1;
    return ESP_OK;
}

/* RFC 4106: nonce = salt || IV, AAD = SPI || seq (|| with the high half first under ESN). */
static size_t build_aad(const esp_sa *sa, uint64_t seq, uint8_t aad[12])
{
    put_be32(aad, sa->spi);
    if (sa->esn) {
        put_be32(aad + 4, (uint32_t)(seq >> 32));
        put_be32(aad + 8, (uint32_t)seq);
        return 12;
    }
    put_be32(aad + 4, (uint32_t)seq);
    return 8;
}

int esp_encap(esp_sa *sa, const uint8_t *payload, size_t len, uint8_t next_hdr,
              uint8_t *out, size_t out_cap)
{
    /* GCM needs no block alignment, but the trailer must end on a 4-byte boundary. */
    size_t pad = (4 - (len + 2) % 4) % 4;
    size_t ct_len = len + pad + 2;
    size_t total = ESP_HDR_LEN + ESP_IV_LEN + ct_len + ESP_ICV_LEN;
    if (total > out_cap)
        return ESP_ERR_SPACE;
    if (sa->esn ? sa->seq == UINT64_MAX : sa->seq == UINT32_MAX)
        return ESP_ERR_SEQ_OVERFLOW; /* the counter must never cycle (RFC 4303 3.3.3) */
    uint64_t seq = ++sa->seq;

    put_be32(out, sa->spi);
    put_be32(out + 4, (uint32_t)seq);
    /* The IV only has to be unique per key; the 64-bit sequence number already is. */
    uint8_t *iv = out + ESP_HDR_LEN;
    put_be32(iv, (uint32_t)(seq >> 32));
    put_be32(iv + 4, (uint32_t)seq);

    uint8_t *ct = iv + ESP_IV_LEN;
    memmove(ct, payload, len);
    for (size_t i = 0; i < pad; i++)
        ct[len + i] = (uint8_t)(i + 1);
    ct[len + pad] = (uint8_t)pad;
    ct[len + pad + 1] = next_hdr;

    uint8_t nonce[GCM_IV_LEN], aad[12];
    memcpy(nonce, sa->salt, ESP_SALT_LEN);
    memcpy(nonce + ESP_SALT_LEN, iv, ESP_IV_LEN);
    size_t aad_len = build_aad(sa, seq, aad);
    gcm_seal(&sa->gcm, nonce, aad, aad_len, ct, ct_len, ct, ct + ct_len);

    sa->stats.packets++;
    sa->stats.bytes += len;
    return (int)total;
}

static int fail(esp_sa *sa, int err)
{
    switch (err) {
    case ESP_ERR_AUTH: sa->stats.err_auth++; break;
    case ESP_ERR_REPLAY: sa->stats.err_replay++; break;
    case ESP_ERR_STALE: sa->stats.err_stale++; break;
    case ESP_ERR_PADDING: sa->stats.err_padding++; break;
    default: sa->stats.err_other++; break;
    }
    return err;
}

int esp_decap(esp_sa *sa, const uint8_t *pkt, size_t len,
              uint8_t *out, size_t out_cap, uint8_t *next_hdr)
{
    /* smallest packet: header + IV + (pad_len, next_hdr) + ICV */
    if (len < ESP_HDR_LEN + ESP_IV_LEN + 2 + ESP_ICV_LEN)
        return fail(sa, ESP_ERR_TRUNCATED);
    if (get_be32(pkt) != sa->spi)
        return fail(sa, ESP_ERR_SPI);

    uint32_t seq_lo = get_be32(pkt + 4);
    uint64_t seq = seq_lo;
    if (sa->esn)
        seq |= (uint64_t)replay_infer_esn_hi(&sa->replay, seq_lo) << 32;

    /* Cheap replay check first so duplicates never cost a GCM pass. */
    switch (replay_check(&sa->replay, seq)) {
    case REPLAY_DUP: return fail(sa, ESP_ERR_REPLAY);
    case REPLAY_STALE: return fail(sa, ESP_ERR_STALE);
    case REPLAY_OK: break;
    }

    const uint8_t *iv = pkt + ESP_HDR_LEN;
    const uint8_t *ct = iv + ESP_IV_LEN;
    size_t ct_len = len - ESP_HDR_LEN - ESP_IV_LEN - ESP_ICV_LEN;
    if (ct_len > out_cap)
        return fail(sa, ESP_ERR_SPACE);

    uint8_t nonce[GCM_IV_LEN], aad[12];
    memcpy(nonce, sa->salt, ESP_SALT_LEN);
    memcpy(nonce + ESP_SALT_LEN, iv, ESP_IV_LEN);
    size_t aad_len = build_aad(sa, seq, aad);
    /* Under ESN a wrong guess of the high bits just makes the ICV fail. */
    if (gcm_open(&sa->gcm, nonce, aad, aad_len, ct, ct_len, ct + ct_len, ESP_ICV_LEN, out) != GCM_OK)
        return fail(sa, ESP_ERR_AUTH);

    size_t pad = out[ct_len - 2];
    if (pad + 2 > ct_len) {
        memset(out, 0, ct_len);
        return fail(sa, ESP_ERR_PADDING);
    }
    size_t payload_len = ct_len - 2 - pad;
    if (sa->check_padding)
        for (size_t i = 0; i < pad; i++)
            if (out[payload_len + i] != (uint8_t)(i + 1)) {
                memset(out, 0, ct_len);
                return fail(sa, ESP_ERR_PADDING);
            }

    /* Authenticated: now it is safe to move the window. */
    replay_update(&sa->replay, seq);
    *next_hdr = out[ct_len - 1];
    sa->stats.packets++;
    sa->stats.bytes += payload_len;
    return (int)payload_len;
}

const char *esp_strerror(int err)
{
    switch (err) {
    case ESP_OK: return "ok";
    case ESP_ERR_PARAM: return "invalid parameter";
    case ESP_ERR_SPACE: return "output buffer too small";
    case ESP_ERR_SEQ_OVERFLOW: return "sequence number overflow (rekey required)";
    case ESP_ERR_TRUNCATED: return "truncated packet";
    case ESP_ERR_SPI: return "unknown SPI";
    case ESP_ERR_REPLAY: return "replayed sequence number";
    case ESP_ERR_STALE: return "sequence number outside replay window";
    case ESP_ERR_AUTH: return "ICV verification failed";
    case ESP_ERR_PADDING: return "invalid padding";
    }
    return "unknown error";
}
