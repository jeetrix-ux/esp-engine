/* Heap-allocated handles for language bindings (the Python tests use ctypes),
 * so callers never have to mirror the C struct layouts. */
#include "esp.h"

#include <stdlib.h>

esp_sa *esp_sa_new(uint32_t spi, const uint8_t *key, size_t key_len, int esn,
                   uint32_t window, int aes, int ghash)
{
    esp_sa_config cfg = {
        .spi = spi, .key = key, .key_len = key_len, .esn = esn, .replay_window = window,
        .aes = (enum aes_impl)aes, .ghash = (enum ghash_impl)ghash,
    };
    esp_sa *sa = malloc(sizeof *sa);
    if (sa && esp_sa_init(sa, &cfg) != ESP_OK) {
        free(sa);
        return NULL;
    }
    return sa;
}

void esp_sa_free(esp_sa *sa) { free(sa); }
void esp_sa_set_seq(esp_sa *sa, uint64_t seq) { sa->seq = seq; }
void esp_sa_set_check_padding(esp_sa *sa, int on) { sa->check_padding = on; }
void esp_sa_get_stats(const esp_sa *sa, esp_stats *out) { *out = sa->stats; }
uint64_t esp_sa_replay_last(const esp_sa *sa) { return sa->replay.last; }

gcm_ctx *gcm_new(const uint8_t *key, size_t key_len, int aes, int ghash)
{
    gcm_ctx *c = malloc(sizeof *c);
    if (c && gcm_init(c, key, key_len, (enum aes_impl)aes, (enum ghash_impl)ghash) != GCM_OK) {
        free(c);
        return NULL;
    }
    return c;
}

void gcm_free(gcm_ctx *c) { free(c); }

replay_window *replay_new(uint32_t window)
{
    replay_window *w = malloc(sizeof *w);
    if (w && replay_init(w, window) != 0) {
        free(w);
        return NULL;
    }
    return w;
}

void replay_free(replay_window *w) { free(w); }
