/* Runtime CPU feature detection for the hardware crypto paths. */
#ifndef HWCAPS_H
#define HWCAPS_H

#if defined(__x86_64__) || defined(_M_X64)
#define ESP_X86 1
#include <cpuid.h>

/* CPUID leaf 1, ECX bit 25 = AES-NI, bit 1 = PCLMULQDQ. */
static inline int hw_has_aes(void)
{
    unsigned a, b, c, d;
    if (!__get_cpuid(1, &a, &b, &c, &d))
        return 0;
    return (c & (1u << 25)) && (c & (1u << 1));
}

#elif defined(__aarch64__) && defined(__linux__)
#define ESP_ARM64 1
#include <sys/auxv.h>
/* GCC 12 gates the AES/PMULL intrinsics on "+crypto"; clang takes "aes". */
#if defined(__clang__)
#define ESP_ARM_CRYPTO __attribute__((target("aes")))
#else
#define ESP_ARM_CRYPTO __attribute__((target("+crypto")))
#endif
#ifndef HWCAP_AES
#define HWCAP_AES (1 << 3)
#endif
#ifndef HWCAP_PMULL
#define HWCAP_PMULL (1 << 4)
#endif

static inline int hw_has_aes(void)
{
    unsigned long caps = getauxval(AT_HWCAP);
    return (caps & HWCAP_AES) && (caps & HWCAP_PMULL);
}

#else
static inline int hw_has_aes(void) { return 0; }
#endif

#endif
