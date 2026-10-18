/* AES block cipher (FIPS-197), encryption direction only.
 * GCM runs AES in counter mode, so the inverse cipher is never needed. */
#ifndef AES_H
#define AES_H

#include <stddef.h>
#include <stdint.h>

/* Which implementation encrypts the blocks. */
enum aes_impl {
    AES_IMPL_REF = 0,   /* byte-oriented, straight from the FIPS-197 pseudocode */
    AES_IMPL_TABLE = 1, /* 32-bit T-tables: SubBytes+ShiftRows+MixColumns as 4 lookups/column */
    AES_IMPL_HW = 2,    /* AES-NI on x86-64, ARMv8 Crypto Extensions on AArch64 */
};

typedef struct {
    uint8_t rk[240];     /* round keys, byte order (also what AES-NI / ARMv8 CE load) */
    uint32_t rkw[60];    /* same round keys as big-endian words for the T-table path */
    int nr;              /* rounds: 10, 12 or 14 */
    enum aes_impl impl;
} aes_key;

/* Returns 0, or -1 for a bad key length or an implementation this CPU lacks. */
int aes_set_key(aes_key *k, const uint8_t *key, size_t key_len, enum aes_impl impl);
void aes_encrypt_block(const aes_key *k, const uint8_t in[16], uint8_t out[16]);

/* Counter mode with a 32-bit big-endian counter in bytes 12..15 (GCM's inc32).
 * Starts from `ctr`, which is advanced past the blocks used; in and out may alias.
 * The hardware path keeps 8 blocks in flight to hide the AES round latency. */
void aes_ctr32_xor(const aes_key *k, uint8_t ctr[16], const uint8_t *in, size_t n, uint8_t *out);

/* 1 if the hardware path is usable on this CPU. */
int aes_hw_available(void);

#endif
