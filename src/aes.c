/* AES-128/192/256 encryption: reference, T-table and hardware paths. */
#include "aes.h"
#include "hwcaps.h"

#include <string.h>

static uint8_t sbox[256];
static uint32_t te0[256], te1[256], te2[256], te3[256];
static int tables_ready;

/* Multiply by x in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1. */
static uint8_t xtime(uint8_t a) { return (uint8_t)((a << 1) ^ ((a >> 7) * 0x1b)); }

static uint8_t gmul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    while (b) {
        if (b & 1)
            p ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return p;
}

static uint8_t rotl8(uint8_t x, int s) { return (uint8_t)((x << s) | (x >> (8 - s))); }

/* Build the S-box from its definition (inverse in GF(2^8), then the affine map)
 * instead of pasting 256 magic numbers; the KAT tests catch any slip. */
static void build_tables(void)
{
    if (tables_ready)
        return;
    uint8_t p = 1, q = 1;
    /* Walk p over the multiplicative group with generator 3 and q over its inverse. */
    do {
        p = (uint8_t)(p ^ xtime(p));          /* p *= 3 */
        q ^= (uint8_t)(q << 1);               /* q /= 3 */
        q ^= (uint8_t)(q << 2);
        q ^= (uint8_t)(q << 4);
        if (q & 0x80)
            q ^= 0x09;
        uint8_t x = (uint8_t)(q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4));
        sbox[p] = (uint8_t)(x ^ 0x63);
    } while (p != 1);
    sbox[0] = 0x63; /* 0 has no inverse */

    for (int i = 0; i < 256; i++) {
        uint8_t s = sbox[i];
        /* column (2s, s, s, 3s) packed big-endian */
        uint32_t t = ((uint32_t)gmul(s, 2) << 24) | ((uint32_t)s << 16) |
                     ((uint32_t)s << 8) | gmul(s, 3);
        te0[i] = t;
        te1[i] = (t >> 8) | (t << 24);
        te2[i] = (t >> 16) | (t << 16);
        te3[i] = (t >> 24) | (t << 8);
    }
    tables_ready = 1;
}

static uint32_t sub_word(uint32_t w)
{
    return ((uint32_t)sbox[w >> 24] << 24) | ((uint32_t)sbox[(w >> 16) & 0xff] << 16) |
           ((uint32_t)sbox[(w >> 8) & 0xff] << 8) | sbox[w & 0xff];
}

int aes_set_key(aes_key *k, const uint8_t *key, size_t key_len, enum aes_impl impl)
{
    int nk;
    switch (key_len) {
    case 16: nk = 4; break;
    case 24: nk = 6; break;
    case 32: nk = 8; break;
    default: return -1;
    }
    if (impl == AES_IMPL_HW && !aes_hw_available())
        return -1;
    build_tables();

    k->nr = nk + 6;
    k->impl = impl;
    int words = 4 * (k->nr + 1);
    uint32_t rcon = 0x01;
    for (int i = 0; i < nk; i++)
        k->rkw[i] = ((uint32_t)key[4 * i] << 24) | ((uint32_t)key[4 * i + 1] << 16) |
                    ((uint32_t)key[4 * i + 2] << 8) | key[4 * i + 3];
    for (int i = nk; i < words; i++) {
        uint32_t t = k->rkw[i - 1];
        if (i % nk == 0) {
            t = sub_word((t << 8) | (t >> 24)) ^ (rcon << 24);
            rcon = xtime((uint8_t)rcon);
        } else if (nk > 6 && i % nk == 4) {
            t = sub_word(t);
        }
        k->rkw[i] = k->rkw[i - nk] ^ t;
    }
    for (int i = 0; i < words; i++) {
        k->rk[4 * i] = (uint8_t)(k->rkw[i] >> 24);
        k->rk[4 * i + 1] = (uint8_t)(k->rkw[i] >> 16);
        k->rk[4 * i + 2] = (uint8_t)(k->rkw[i] >> 8);
        k->rk[4 * i + 3] = (uint8_t)k->rkw[i];
    }
    return 0;
}

/* ---- reference: one FIPS-197 step at a time, state as 16 bytes column-major ---- */

static void add_round_key(uint8_t s[16], const uint8_t *rk)
{
    for (int i = 0; i < 16; i++)
        s[i] ^= rk[i];
}

static void sub_bytes(uint8_t s[16])
{
    for (int i = 0; i < 16; i++)
        s[i] = sbox[s[i]];
}

/* Row r of the state is bytes r, r+4, r+8, r+12; rotate row r left by r. */
static void shift_rows(uint8_t s[16])
{
    uint8_t t[16];
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            t[4 * c + r] = s[4 * ((c + r) % 4) + r];
    memcpy(s, t, 16);
}

static void mix_columns(uint8_t s[16])
{
    for (int c = 0; c < 4; c++) {
        uint8_t *col = s + 4 * c;
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        col[0] = (uint8_t)(xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3);
        col[1] = (uint8_t)(a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3);
        col[2] = (uint8_t)(a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3));
        col[3] = (uint8_t)((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3));
    }
}

static void encrypt_ref(const aes_key *k, const uint8_t in[16], uint8_t out[16])
{
    uint8_t s[16];
    memcpy(s, in, 16);
    add_round_key(s, k->rk);
    for (int r = 1; r < k->nr; r++) {
        sub_bytes(s);
        shift_rows(s);
        mix_columns(s);
        add_round_key(s, k->rk + 16 * r);
    }
    sub_bytes(s);
    shift_rows(s);
    add_round_key(s, k->rk + 16 * k->nr);
    memcpy(out, s, 16);
}

/* ---- T-table: each output column is 4 table lookups XORed with the round key ----
 * Not constant-time: table indices depend on secret state, so cache timing can
 * leak key bits on a shared core. The HW path exists for exactly that reason. */

static uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void encrypt_table(const aes_key *k, const uint8_t in[16], uint8_t out[16])
{
    const uint32_t *rk = k->rkw;
    uint32_t s0 = load_be32(in) ^ rk[0];
    uint32_t s1 = load_be32(in + 4) ^ rk[1];
    uint32_t s2 = load_be32(in + 8) ^ rk[2];
    uint32_t s3 = load_be32(in + 12) ^ rk[3];
    uint32_t t0, t1, t2, t3;

    for (int r = 1; r < k->nr; r++) {
        rk += 4;
        t0 = te0[s0 >> 24] ^ te1[(s1 >> 16) & 0xff] ^ te2[(s2 >> 8) & 0xff] ^ te3[s3 & 0xff] ^ rk[0];
        t1 = te0[s1 >> 24] ^ te1[(s2 >> 16) & 0xff] ^ te2[(s3 >> 8) & 0xff] ^ te3[s0 & 0xff] ^ rk[1];
        t2 = te0[s2 >> 24] ^ te1[(s3 >> 16) & 0xff] ^ te2[(s0 >> 8) & 0xff] ^ te3[s1 & 0xff] ^ rk[2];
        t3 = te0[s3 >> 24] ^ te1[(s0 >> 16) & 0xff] ^ te2[(s1 >> 8) & 0xff] ^ te3[s2 & 0xff] ^ rk[3];
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }
    rk += 4;
    /* last round: no MixColumns, so use the plain S-box */
#define LAST(a, b, c, d) \
    (((uint32_t)sbox[(a) >> 24] << 24) | ((uint32_t)sbox[((b) >> 16) & 0xff] << 16) | \
     ((uint32_t)sbox[((c) >> 8) & 0xff] << 8) | sbox[(d) & 0xff])
    store_be32(out, LAST(s0, s1, s2, s3) ^ rk[0]);
    store_be32(out + 4, LAST(s1, s2, s3, s0) ^ rk[1]);
    store_be32(out + 8, LAST(s2, s3, s0, s1) ^ rk[2]);
    store_be32(out + 12, LAST(s3, s0, s1, s2) ^ rk[3]);
#undef LAST
}

/* ---- hardware ---- */

#if defined(ESP_X86)
#include <wmmintrin.h>

__attribute__((target("aes,sse2")))
static void encrypt_hw(const aes_key *k, const uint8_t in[16], uint8_t out[16])
{
    __m128i s = _mm_loadu_si128((const __m128i *)in);
    s = _mm_xor_si128(s, _mm_loadu_si128((const __m128i *)k->rk));
    for (int r = 1; r < k->nr; r++)
        s = _mm_aesenc_si128(s, _mm_loadu_si128((const __m128i *)(k->rk + 16 * r)));
    s = _mm_aesenclast_si128(s, _mm_loadu_si128((const __m128i *)(k->rk + 16 * k->nr)));
    _mm_storeu_si128((__m128i *)out, s);
}

int aes_hw_available(void) { return hw_has_aes(); }

/* AESENC has a latency of several cycles but can issue every cycle, so one block
 * at a time leaves the unit mostly idle. Eight independent counter blocks per
 * round keep it busy. Returns the bytes processed (a multiple of 128). */
#define HAVE_CTR_HW 1
__attribute__((target("aes,sse2")))
static size_t ctr_hw(const aes_key *k, uint8_t ctr[16], const uint8_t *in, size_t n, uint8_t *out)
{
    __m128i rk[15];
    for (int r = 0; r <= k->nr; r++)
        rk[r] = _mm_loadu_si128((const __m128i *)(k->rk + 16 * r));
    uint32_t c = load_be32(ctr + 12);
    uint8_t blk[8][16];
    size_t done = 0;
    for (; n - done >= 128; done += 128, c += 8) {
        __m128i s[8];
        for (int i = 0; i < 8; i++) {
            memcpy(blk[i], ctr, 12);
            store_be32(blk[i] + 12, c + (uint32_t)i);
            s[i] = _mm_xor_si128(_mm_loadu_si128((const __m128i *)blk[i]), rk[0]);
        }
        for (int r = 1; r < k->nr; r++)
            for (int i = 0; i < 8; i++)
                s[i] = _mm_aesenc_si128(s[i], rk[r]);
        for (int i = 0; i < 8; i++) {
            s[i] = _mm_aesenclast_si128(s[i], rk[k->nr]);
            s[i] = _mm_xor_si128(s[i], _mm_loadu_si128((const __m128i *)(in + done + 16 * i)));
            _mm_storeu_si128((__m128i *)(out + done + 16 * i), s[i]);
        }
    }
    store_be32(ctr + 12, c);
    return done;
}

#elif defined(ESP_ARM64)
#include <arm_neon.h>

/* AESE = AddRoundKey + SubBytes + ShiftRows, AESMC = MixColumns, so the
 * round-key XOR sits at the start of each round instead of the end. */
ESP_ARM_CRYPTO
static void encrypt_hw(const aes_key *k, const uint8_t in[16], uint8_t out[16])
{
    uint8x16_t s = vld1q_u8(in);
    for (int r = 0; r < k->nr - 1; r++)
        s = vaesmcq_u8(vaeseq_u8(s, vld1q_u8(k->rk + 16 * r)));
    s = vaeseq_u8(s, vld1q_u8(k->rk + 16 * (k->nr - 1)));
    s = veorq_u8(s, vld1q_u8(k->rk + 16 * k->nr));
    vst1q_u8(out, s);
}

int aes_hw_available(void) { return hw_has_aes(); }

/* Eight blocks in flight, as on x86. */
#define HAVE_CTR_HW 1
ESP_ARM_CRYPTO
static size_t ctr_hw(const aes_key *k, uint8_t ctr[16], const uint8_t *in, size_t n, uint8_t *out)
{
    uint32_t c = load_be32(ctr + 12);
    uint8_t blk[8][16];
    size_t done = 0;
    for (; n - done >= 128; done += 128, c += 8) {
        uint8x16_t s[8];
        for (int i = 0; i < 8; i++) {
            memcpy(blk[i], ctr, 12);
            store_be32(blk[i] + 12, c + (uint32_t)i);
            s[i] = vld1q_u8(blk[i]);
        }
        for (int r = 0; r < k->nr - 1; r++) {
            uint8x16_t key = vld1q_u8(k->rk + 16 * r);
            for (int i = 0; i < 8; i++)
                s[i] = vaesmcq_u8(vaeseq_u8(s[i], key));
        }
        uint8x16_t kl = vld1q_u8(k->rk + 16 * (k->nr - 1)), kf = vld1q_u8(k->rk + 16 * k->nr);
        for (int i = 0; i < 8; i++) {
            s[i] = veorq_u8(vaeseq_u8(s[i], kl), kf);
            vst1q_u8(out + done + 16 * i, veorq_u8(s[i], vld1q_u8(in + done + 16 * i)));
        }
    }
    store_be32(ctr + 12, c);
    return done;
}

#else
static void encrypt_hw(const aes_key *k, const uint8_t in[16], uint8_t out[16])
{
    encrypt_table(k, in, out);
}

int aes_hw_available(void) { return 0; }
#endif

void aes_encrypt_block(const aes_key *k, const uint8_t in[16], uint8_t out[16])
{
    switch (k->impl) {
    case AES_IMPL_REF: encrypt_ref(k, in, out); break;
    case AES_IMPL_TABLE: encrypt_table(k, in, out); break;
    case AES_IMPL_HW: encrypt_hw(k, in, out); break;
    }
}

void aes_ctr32_xor(const aes_key *k, uint8_t ctr[16], const uint8_t *in, size_t n, uint8_t *out)
{
#ifdef HAVE_CTR_HW
    if (k->impl == AES_IMPL_HW) {
        size_t done = ctr_hw(k, ctr, in, n, out);
        in += done;
        out += done;
        n -= done;
    }
#endif
    uint8_t ks[16];
    while (n) {
        aes_encrypt_block(k, ctr, ks);
        size_t take = n < 16 ? n : 16;
        for (size_t i = 0; i < take; i++)
            out[i] = in[i] ^ ks[i];
        store_be32(ctr + 12, load_be32(ctr + 12) + 1);
        in += take;
        out += take;
        n -= take;
    }
}
