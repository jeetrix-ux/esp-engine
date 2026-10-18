/* AES-GCM: CTR-mode encryption plus GHASH over GF(2^128). */
#include "gcm.h"
#include "hwcaps.h"

#include <string.h>

/* ---- GHASH multiply, reference ----
 * GCM's bit order is reflected: bit 0 of the field element is the MSB of byte 0.
 * Multiplying by x is therefore a right shift, and the reduction polynomial
 * x^128 + x^7 + x^2 + x + 1 shows up as 0xe1 in the top byte. */
static void mult_ref(const uint8_t h[16], uint8_t x[16])
{
    uint8_t z[16] = {0}, v[16];
    memcpy(v, h, 16);
    for (int i = 0; i < 128; i++) {
        if (x[i >> 3] & (0x80 >> (i & 7)))
            for (int j = 0; j < 16; j++)
                z[j] ^= v[j];
        int lsb = v[15] & 1;
        for (int j = 15; j > 0; j--)
            v[j] = (uint8_t)((v[j] >> 1) | (v[j - 1] << 7));
        v[0] >>= 1;
        if (lsb)
            v[0] ^= 0xe1;
    }
    memcpy(x, z, 16);
}

/* ---- GHASH multiply, 4-bit table (Shoup) ----
 * hh/hl[i] hold i*H for every 4-bit i, so a multiply is 32 lookups, each followed by
 * a 4-bit shift of the accumulator. The bits shifted out are folded back in
 * through last4[], the reduction of those 4 bits. */
static const uint64_t last4[16] = {
    0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
    0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0,
};

static uint64_t load_be64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v = (v << 8) | p[i];
    return v;
}

static void store_be64(uint8_t *p, uint64_t v)
{
    for (int i = 7; i >= 0; i--) {
        p[i] = (uint8_t)v;
        v >>= 8;
    }
}

static void table_init(gcm_ctx *c)
{
    uint64_t vh = load_be64(c->h), vl = load_be64(c->h + 8);
    c->hh[0] = c->hl[0] = 0;
    c->hh[8] = vh;
    c->hl[8] = vl;
    /* entries 4, 2, 1: successive multiplications of H by x (right shifts) */
    for (int i = 4; i > 0; i >>= 1) {
        uint64_t t = (vl & 1) * 0xe1000000u;
        vl = (vh << 63) | (vl >> 1);
        vh = (vh >> 1) ^ (t << 32);
        c->hh[i] = vh;
        c->hl[i] = vl;
    }
    /* the rest are XOR combinations of the powers above */
    for (int i = 2; i <= 8; i *= 2)
        for (int j = 1; j < i; j++) {
            c->hh[i + j] = c->hh[i] ^ c->hh[j];
            c->hl[i + j] = c->hl[i] ^ c->hl[j];
        }
}

static void mult_table(const gcm_ctx *c, uint8_t x[16])
{
    int lo = x[15] & 0xf;
    uint64_t zh = c->hh[lo], zl = c->hl[lo];
    for (int i = 15; i >= 0; i--) {
        lo = x[i] & 0xf;
        int hi = x[i] >> 4;
        if (i != 15) {
            int rem = (int)(zl & 0xf);
            zl = (zh << 60) | (zl >> 4);
            zh = (zh >> 4) ^ (last4[rem] << 48);
            zh ^= c->hh[lo];
            zl ^= c->hl[lo];
        }
        int rem = (int)(zl & 0xf);
        zl = (zh << 60) | (zl >> 4);
        zh = (zh >> 4) ^ (last4[rem] << 48);
        zh ^= c->hh[hi];
        zl ^= c->hl[hi];
    }
    store_be64(x, zh);
    store_be64(x + 8, zl);
}

/* ---- GHASH multiply, carry-less multiply instructions ----
 * Byte-swap both operands so the reflected GCM element becomes an ordinary
 * polynomial, take the 256-bit carry-less product with four 64x64 multiplies,
 * shift it left one bit (reflection leaves the product off by one), then reduce
 * modulo x^128 + x^7 + x^2 + x + 1 with shifts and XORs. */
#if defined(ESP_X86)
#include <emmintrin.h>
#include <tmmintrin.h>
#include <wmmintrin.h>

#define CLMUL __attribute__((target("pclmul,ssse3")))

CLMUL static inline __m128i bswap128(__m128i v)
{
    return _mm_shuffle_epi8(v, _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15));
}

CLMUL static inline __m128i load_swapped(const uint8_t *p)
{
    return bswap128(_mm_loadu_si128((const __m128i *)p));
}

/* Unreduced 256-bit carry-less product, accumulated into lo:hi. */
CLMUL static inline void clmul_acc(__m128i a, __m128i b, __m128i *lo, __m128i *hi)
{
    __m128i l = _mm_clmulepi64_si128(a, b, 0x00);
    __m128i mid = _mm_xor_si128(_mm_clmulepi64_si128(a, b, 0x10),
                                _mm_clmulepi64_si128(a, b, 0x01));
    __m128i h = _mm_clmulepi64_si128(a, b, 0x11);
    *lo = _mm_xor_si128(*lo, _mm_xor_si128(l, _mm_slli_si128(mid, 8)));
    *hi = _mm_xor_si128(*hi, _mm_xor_si128(h, _mm_srli_si128(mid, 8)));
}

/* Shift-and-reduce is linear, so a sum of several unreduced products can share
 * one reduction; that is the whole trick behind aggregated GHASH. */
CLMUL static inline __m128i reduce(__m128i lo, __m128i hi)
{
    /* 256-bit <<1 across the lo:hi pair */
    __m128i lo_c = _mm_srli_epi32(lo, 31), hi_c = _mm_srli_epi32(hi, 31);
    lo = _mm_slli_epi32(lo, 1);
    hi = _mm_slli_epi32(hi, 1);
    __m128i carry = _mm_srli_si128(lo_c, 12);
    hi_c = _mm_slli_si128(hi_c, 4);
    lo_c = _mm_slli_si128(lo_c, 4);
    lo = _mm_or_si128(lo, lo_c);
    hi = _mm_or_si128(_mm_or_si128(hi, hi_c), carry);

    /* reduction, first phase */
    __m128i t = _mm_xor_si128(_mm_xor_si128(_mm_slli_epi32(lo, 31), _mm_slli_epi32(lo, 30)),
                              _mm_slli_epi32(lo, 25));
    __m128i t_hi = _mm_srli_si128(t, 4);
    lo = _mm_xor_si128(lo, _mm_slli_si128(t, 12));
    /* second phase */
    __m128i u = _mm_xor_si128(_mm_xor_si128(_mm_srli_epi32(lo, 1), _mm_srli_epi32(lo, 2)),
                              _mm_srli_epi32(lo, 7));
    u = _mm_xor_si128(u, t_hi);
    lo = _mm_xor_si128(lo, u);
    return _mm_xor_si128(hi, lo);
}

CLMUL static void mult_hw(const uint8_t h[16], uint8_t x[16])
{
    __m128i lo = _mm_setzero_si128(), hi = _mm_setzero_si128();
    clmul_acc(load_swapped(x), load_swapped(h), &lo, &hi);
    _mm_storeu_si128((__m128i *)x, bswap128(reduce(lo, hi)));
}

/* GHASH over whole blocks, four at a time:
 *   Y' = (Y ^ X0)*H^4 ^ X1*H^3 ^ X2*H^2 ^ X3*H
 * Four independent multiplies keep the PCLMULQDQ pipeline full, and there is
 * one reduction per four blocks instead of one per block. */
#define HAVE_GHASH_BLOCKS 1
CLMUL static void ghash_blocks_hw(const gcm_ctx *c, uint8_t y[16], const uint8_t *p, size_t nblocks)
{
    __m128i h1 = load_swapped(c->hpow[0]), h2 = load_swapped(c->hpow[1]);
    __m128i h3 = load_swapped(c->hpow[2]), h4 = load_swapped(c->hpow[3]);
    __m128i acc = load_swapped(y);
    for (; nblocks >= 4; nblocks -= 4, p += 64) {
        __m128i lo = _mm_setzero_si128(), hi = _mm_setzero_si128();
        clmul_acc(_mm_xor_si128(acc, load_swapped(p)), h4, &lo, &hi);
        clmul_acc(load_swapped(p + 16), h3, &lo, &hi);
        clmul_acc(load_swapped(p + 32), h2, &lo, &hi);
        clmul_acc(load_swapped(p + 48), h1, &lo, &hi);
        acc = reduce(lo, hi);
    }
    for (; nblocks; nblocks--, p += 16) {
        __m128i lo = _mm_setzero_si128(), hi = _mm_setzero_si128();
        clmul_acc(_mm_xor_si128(acc, load_swapped(p)), h1, &lo, &hi);
        acc = reduce(lo, hi);
    }
    _mm_storeu_si128((__m128i *)y, bswap128(acc));
}

#elif defined(ESP_ARM64)
#include <arm_neon.h>

/* Same algorithm on PMULL. GCM's reflected bit order is handled by reversing the
 * bits within each byte (RBIT) on the way in and out; after that the field is an
 * ordinary polynomial with byte 0 as the least significant byte. */
ESP_ARM_CRYPTO
static void mult_hw(const uint8_t h[16], uint8_t x[16])
{
    uint8x16_t a8 = vrbitq_u8(vld1q_u8(x)), b8 = vrbitq_u8(vld1q_u8(h));
    poly64x2_t a = vreinterpretq_p64_u8(a8), b = vreinterpretq_p64_u8(b8);

    poly64_t a0 = vgetq_lane_p64(a, 0), a1 = vgetq_lane_p64(a, 1);
    poly64_t b0 = vgetq_lane_p64(b, 0), b1 = vgetq_lane_p64(b, 1);
    uint64x2_t lo = vreinterpretq_u64_p128(vmull_p64(a0, b0));
    uint64x2_t hi = vreinterpretq_u64_p128(vmull_p64(a1, b1));
    uint64x2_t mid = veorq_u64(vreinterpretq_u64_p128(vmull_p64(a0, b1)),
                               vreinterpretq_u64_p128(vmull_p64(a1, b0)));
    /* lo += mid << 64, hi += mid >> 64 */
    lo = veorq_u64(lo, vcombine_u64(vdup_n_u64(0), vget_low_u64(mid)));
    hi = veorq_u64(hi, vcombine_u64(vget_high_u64(mid), vdup_n_u64(0)));

    /* Reduce hi*x^128 + lo using x^128 = x^7 + x^2 + x + 1 (0x87), one 64-bit
     * half at a time. h1*x^192 folds to (h1*0x87)*x^64, whose top 7 bits land
     * back in h0; then h0*x^128 folds to h0*0x87. */
    uint64_t h0 = vgetq_lane_u64(hi, 0), h1 = vgetq_lane_u64(hi, 1);
    uint64x2_t f = vreinterpretq_u64_p128(vmull_p64(h1, 0x87));
    lo = veorq_u64(lo, vcombine_u64(vdup_n_u64(0), vget_low_u64(f)));
    h0 ^= vgetq_lane_u64(f, 1);
    uint64x2_t g = vreinterpretq_u64_p128(vmull_p64(h0, 0x87));
    lo = veorq_u64(lo, g);

    vst1q_u8(x, vrbitq_u8(vreinterpretq_u8_u64(lo)));
}
#else
static void mult_hw(const uint8_t h[16], uint8_t x[16]) { mult_ref(h, x); }
#endif

void gcm_ghash_mult(const gcm_ctx *c, uint8_t x[16])
{
    switch (c->ghash) {
    case GHASH_IMPL_REF: mult_ref(c->h, x); break;
    case GHASH_IMPL_TABLE: mult_table(c, x); break;
    case GHASH_IMPL_HW: mult_hw(c->h, x); break;
    }
}

int gcm_init(gcm_ctx *c, const uint8_t *key, size_t key_len,
             enum aes_impl aes, enum ghash_impl ghash)
{
    memset(c, 0, sizeof *c);
    if (ghash == GHASH_IMPL_HW && !hw_has_aes())
        return GCM_ERR_KEY;
    if (aes_set_key(&c->aes, key, key_len, aes) != 0)
        return GCM_ERR_KEY;
    c->ghash = ghash;
    uint8_t zero[16] = {0};
    aes_encrypt_block(&c->aes, zero, c->h);
    table_init(c);
    /* H, H^2, H^3, H^4 for the aggregated GHASH path */
    memcpy(c->hpow[0], c->h, 16);
    for (int i = 1; i < 4; i++) {
        memcpy(c->hpow[i], c->hpow[i - 1], 16);
        mult_ref(c->h, c->hpow[i]);
    }
    return GCM_OK;
}

/* Absorb data into the GHASH state, zero-padding the final partial block. */
static void ghash_update(const gcm_ctx *c, uint8_t y[16], const uint8_t *p, size_t n)
{
#ifdef HAVE_GHASH_BLOCKS
    if (c->ghash == GHASH_IMPL_HW && n >= 16) {
        ghash_blocks_hw(c, y, p, n / 16);
        p += n & ~(size_t)15;
        n &= 15;
    }
#endif
    while (n >= 16) {
        for (int i = 0; i < 16; i++)
            y[i] ^= p[i];
        gcm_ghash_mult(c, y);
        p += 16;
        n -= 16;
    }
    if (n) {
        for (size_t i = 0; i < n; i++)
            y[i] ^= p[i];
        gcm_ghash_mult(c, y);
    }
}

/* CTR mode starting from inc32(J0), where J0 = IV || 0^31 || 1. */
static void ctr_xor(const gcm_ctx *c, const uint8_t iv[GCM_IV_LEN],
                    const uint8_t *in, size_t n, uint8_t *out)
{
    uint8_t ctr[16];
    memcpy(ctr, iv, 12);
    ctr[12] = ctr[13] = ctr[14] = 0;
    ctr[15] = 2;
    aes_ctr32_xor(&c->aes, ctr, in, n, out);
}

static void compute_tag(const gcm_ctx *c, const uint8_t iv[GCM_IV_LEN],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *ct, size_t len, uint8_t tag[16])
{
    uint8_t y[16] = {0}, lens[16], j0[16];
    ghash_update(c, y, aad, aad_len);
    ghash_update(c, y, ct, len);
    store_be64(lens, (uint64_t)aad_len * 8);
    store_be64(lens + 8, (uint64_t)len * 8);
    ghash_update(c, y, lens, 16);

    memcpy(j0, iv, 12);
    j0[12] = j0[13] = j0[14] = 0;
    j0[15] = 1;
    aes_encrypt_block(&c->aes, j0, tag);
    for (int i = 0; i < 16; i++)
        tag[i] ^= y[i];
}

void gcm_seal(const gcm_ctx *c, const uint8_t iv[GCM_IV_LEN],
              const uint8_t *aad, size_t aad_len,
              const uint8_t *pt, size_t len, uint8_t *ct, uint8_t tag[GCM_TAG_LEN])
{
    ctr_xor(c, iv, pt, len, ct);
    compute_tag(c, iv, aad, aad_len, ct, len, tag);
}

int gcm_open(const gcm_ctx *c, const uint8_t iv[GCM_IV_LEN],
             const uint8_t *aad, size_t aad_len,
             const uint8_t *ct, size_t len, const uint8_t *tag, size_t tag_len,
             uint8_t *pt)
{
    uint8_t want[16];
    if (tag_len == 0 || tag_len > 16)
        return GCM_ERR_AUTH;
    compute_tag(c, iv, aad, aad_len, ct, len, want);
    /* constant-time compare: no early exit that would time how many bytes matched */
    uint8_t diff = 0;
    for (size_t i = 0; i < tag_len; i++)
        diff |= want[i] ^ tag[i];
    if (diff) {
        if (pt != ct)
            memset(pt, 0, len);
        return GCM_ERR_AUTH;
    }
    ctr_xor(c, iv, ct, len, pt);
    return GCM_OK;
}
