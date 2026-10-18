/* AES-GCM authenticated encryption (NIST SP 800-38D), 96-bit IVs, 128-bit tags. */
#ifndef GCM_H
#define GCM_H

#include "aes.h"

#include <stddef.h>
#include <stdint.h>

#define GCM_TAG_LEN 16
#define GCM_IV_LEN 12

enum gcm_err {
    GCM_OK = 0,
    GCM_ERR_KEY = -1,
    GCM_ERR_AUTH = -2,  /* tag mismatch: output has been zeroed */
};

/* GHASH multiply implementation; independent of the AES one so each can be benchmarked. */
enum ghash_impl {
    GHASH_IMPL_REF = 0,   /* bit-at-a-time shift-and-add (SP 800-38D Algorithm 1) */
    GHASH_IMPL_TABLE = 1, /* Shoup's 4-bit tables: 16 precomputed multiples of H */
    GHASH_IMPL_HW = 2,    /* PCLMULQDQ on x86-64, PMULL on AArch64 */
};

typedef struct {
    aes_key aes;
    enum ghash_impl ghash;
    uint8_t h[16];          /* hash subkey H = E_K(0^128) */
    uint64_t hl[16], hh[16];/* 4-bit table: low/high halves of i*H */
    uint8_t hpow[4][16];    /* H, H^2, H^3, H^4 for 4-block aggregated GHASH */
} gcm_ctx;

int gcm_init(gcm_ctx *c, const uint8_t *key, size_t key_len,
             enum aes_impl aes, enum ghash_impl ghash);

/* ct and pt may alias. */
void gcm_seal(const gcm_ctx *c, const uint8_t iv[GCM_IV_LEN],
              const uint8_t *aad, size_t aad_len,
              const uint8_t *pt, size_t len, uint8_t *ct, uint8_t tag[GCM_TAG_LEN]);

int gcm_open(const gcm_ctx *c, const uint8_t iv[GCM_IV_LEN],
             const uint8_t *aad, size_t aad_len,
             const uint8_t *ct, size_t len, const uint8_t *tag, size_t tag_len,
             uint8_t *pt);

/* Exposed for the tests: one GHASH multiply, X = X * H. */
void gcm_ghash_mult(const gcm_ctx *c, uint8_t x[16]);

#endif
