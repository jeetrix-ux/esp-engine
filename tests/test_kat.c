/* Known-answer tests for AES and AES-GCM plus a differential check across every
 * implementation pair. Self-contained so it can run under qemu-user on any arch. */
#include "aes.h"
#include "gcm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures, checks;

static size_t unhex(const char *s, uint8_t *out)
{
    size_t n = 0;
    while (s[0] && s[1]) {
        unsigned v;
        sscanf(s, "%2x", &v);
        out[n++] = (uint8_t)v;
        s += 2;
    }
    return n;
}

static void expect(const char *what, const uint8_t *got, const uint8_t *want, size_t n)
{
    checks++;
    if (memcmp(got, want, n) != 0) {
        failures++;
        printf("FAIL %s\n", what);
    }
}

static const char *aes_name[] = {"ref", "table", "hw"};

static void aes_kats(enum aes_impl impl)
{
    /* FIPS-197 Appendix C.1-C.3 */
    static const struct { const char *key, *ct; } v[] = {
        {"000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"},
        {"000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"},
        {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
         "8ea2b7ca516745bfeafc49904b496089"},
    };
    uint8_t key[32], pt[16], want[16], got[16];
    unhex("00112233445566778899aabbccddeeff", pt);
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        aes_key k;
        size_t kl = unhex(v[i].key, key);
        unhex(v[i].ct, want);
        aes_set_key(&k, key, kl, impl);
        aes_encrypt_block(&k, pt, got);
        char name[64];
        snprintf(name, sizeof name, "aes-%zu %s", kl * 8, aes_name[impl]);
        expect(name, got, want, 16);
    }
}

static void gcm_kats(enum aes_impl aes, enum ghash_impl gh)
{
    /* McGrew & Viega, "The Galois/Counter Mode of Operation", test cases 2, 3, 4 and 16 */
    static const struct { const char *k, *iv, *p, *a, *c, *t; } v[] = {
        {"00000000000000000000000000000000", "000000000000000000000000",
         "00000000000000000000000000000000", "",
         "0388dace60b6a392f328c2b971b2fe78", "ab6e47d42cec13bdf53a67b21257bddf"},
        {"feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
         "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
         "",
         "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
         "4d5c2af327cd64a62cf35abd2ba6fab4"},
        {"feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
         "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
         "feedfacedeadbeeffeedfacedeadbeefabaddad2",
         "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
         "5bc94fbc3221a5db94fae95ae7121a47"},
        {"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
         "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
         "feedfacedeadbeeffeedfacedeadbeefabaddad2",
         "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
         "76fc6ece0f4e1768cddf8853bb2d551b"},
    };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        uint8_t k[32], iv[12], p[64], a[32], c[64], t[16], out[64], tag[16], back[64];
        size_t kl = unhex(v[i].k, k), pl = unhex(v[i].p, p), al = unhex(v[i].a, a);
        unhex(v[i].iv, iv);
        unhex(v[i].c, c);
        unhex(v[i].t, t);
        gcm_ctx g;
        gcm_init(&g, k, kl, aes, gh);
        gcm_seal(&g, iv, a, al, p, pl, out, tag);
        char name[64];
        snprintf(name, sizeof name, "gcm#%zu aes=%s ghash=%s", i, aes_name[aes], aes_name[gh]);
        expect(name, out, c, pl);
        expect(name, tag, t, 16);

        checks++;
        if (gcm_open(&g, iv, a, al, out, pl, tag, 16, back) != GCM_OK || memcmp(back, p, pl)) {
            failures++;
            printf("FAIL %s open\n", name);
        }
        tag[0] ^= 1;
        checks++;
        if (gcm_open(&g, iv, a, al, out, pl, tag, 16, back) != GCM_ERR_AUTH) {
            failures++;
            printf("FAIL %s accepted a forged tag\n", name);
        }
    }
}

/* xorshift so the run is reproducible on every arch */
static uint64_t rng_state = 0x9e3779b97f4a7c15ull;
static uint8_t rnd(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (uint8_t)rng_state;
}

/* Every (AES, GHASH) pair must agree with ref/ref on random keys, lengths and AAD. */
static void differential(int hw)
{
    int top = hw ? 3 : 2;
    for (int iter = 0; iter < 600; iter++) {
        uint8_t key[32], iv[12], aad[40], pt[700], ref_ct[700], ref_tag[16];
        size_t kl = (size_t[]){16, 24, 32}[iter % 3];
        size_t len = ((size_t)rnd() << 8 | rnd()) % 700, al = rnd() % 40;
        for (size_t i = 0; i < kl; i++) key[i] = rnd();
        for (int i = 0; i < 12; i++) iv[i] = rnd();
        for (size_t i = 0; i < al; i++) aad[i] = rnd();
        for (size_t i = 0; i < len; i++) pt[i] = rnd();

        gcm_ctx g;
        gcm_init(&g, key, kl, AES_IMPL_REF, GHASH_IMPL_REF);
        gcm_seal(&g, iv, aad, al, pt, len, ref_ct, ref_tag);
        for (int a = 0; a < top; a++)
            for (int h = 0; h < top; h++) {
                uint8_t ct[700], tag[16];
                gcm_init(&g, key, kl, (enum aes_impl)a, (enum ghash_impl)h);
                gcm_seal(&g, iv, aad, al, pt, len, ct, tag);
                checks++;
                if (memcmp(ct, ref_ct, len) || memcmp(tag, ref_tag, 16)) {
                    failures++;
                    printf("FAIL differential iter=%d aes=%s ghash=%s len=%zu\n",
                           iter, aes_name[a], aes_name[h], len);
                }
            }
    }
}

int main(void)
{
    int hw = aes_hw_available();
    printf("hardware crypto path: %s\n", hw ? "available" : "not available");
    for (int a = 0; a < (hw ? 3 : 2); a++) {
        aes_kats((enum aes_impl)a);
        for (int h = 0; h < (hw ? 3 : 2); h++)
            gcm_kats((enum aes_impl)a, (enum ghash_impl)h);
    }
    differential(hw);
    printf("%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
