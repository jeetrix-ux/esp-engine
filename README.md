# esp-engine

A user-space **IPsec ESP** data path in C: AES-GCM written from the NIST specs,
RFC 4303 / RFC 4106 encapsulation with anti-replay and 64-bit extended sequence
numbers, a tunnel daemon that **interoperates with the Linux kernel's IPsec stack**,
and a pytest automation framework that checks it against three independent
references on x86-64, AArch64 and RISC-V.

```
 inner IP packet                                    ESP packet (IP proto 50)
 ┌────────────┐   esp_encap()                      ┌─────┬─────┬────┬───────────────────────────┬─────┐
 │ IP | L4 |..│ ─────────────────────────────────▶ │ SPI │ Seq │ IV │ E(payload|pad|len|nxt hdr) │ ICV │
 └────────────┘   AES-GCM, AAD = SPI || Seq        └─────┴─────┴────┴───────────────────────────┴─────┘
                  nonce = salt || IV                         ◀── authenticated ──▶  ◀ encrypted ▶
```

## Highlights

| | |
|---|---|
| **Crypto** | AES-128/192/256 + GCM from FIPS-197 / SP 800-38D, three interchangeable back-ends: byte-wise reference, T-table + Shoup 4-bit GHASH, and hardware (x86 **AES-NI + PCLMULQDQ**, ARMv8 **AESE/AESMC + PMULL**), picked at run time by CPUID / `getauxval` |
| **Protocol** | RFC 4303 ESP, RFC 4106 nonce/AAD rules, RFC 6479 anti-replay bitmap (64–4096 packets), ESN with the RFC 4303 A2.2 high-bits inference, sequence-overflow refusal, padding checks, per-SA error counters |
| **Interop** | `espd` (TUN + raw socket) ping-tests against **Linux XFRM** `rfc4106(gcm(aes))` in network namespaces, with and without ESN; captured wire packets also decrypt in **Scapy** |
| **Performance** | 8-block interleaved AES-NI CTR + 4-block aggregated GHASH: **11.4 Gbit/s per core at 2.15 cycles/byte** (2.8x over single-block, 164x over the reference), **129 Gbit/s on 16 cores** with one SA per core. See [docs/BENCHMARKS.md](docs/BENCHMARKS.md) |
| **Testing** | 1,886 pytest cases + 5,553 C checks: Wycheproof vectors, Scapy differential tests, model-based replay tests, every-bit-flip / truncation / forged-padding tests, kernel interop, ASan + UBSan, libFuzzer (1.4 M runs / 90 s, 0 findings), CI on x86-64 + AArch64 + RISC-V (QEMU) |

## Build and test

Everything runs in the dev container (Debian, gcc, clang, cross compilers, QEMU, Scapy):

```sh
docker build -t esp-engine-dev .
docker run --rm --privileged -v "$PWD:/src" esp-engine-dev make all test   # --privileged: netns + TUN tests
docker run --rm -v "$PWD:/src" esp-engine-dev make cross     # AArch64 + RISC-V under QEMU
docker run --rm -v "$PWD:/src" esp-engine-dev make asan      # pytest against an ASan/UBSan build
docker run --rm -v "$PWD:/src" esp-engine-dev make fuzz FUZZ_TIME=120
docker run --rm -v "$PWD:/src" esp-engine-dev sh -c 'make bench && build/native/espbench | perl scripts/bench_report.pl'
```

Bring up the kernel-interop tunnel by hand:

```sh
sudo scripts/netns_interop.sh up kernel     # or: up espd   (ESN=1 for extended sequence numbers)
sudo scripts/netns_interop.sh ping
sudo scripts/netns_interop.sh stats         # espd counters + kernel /proc/net/xfrm_stat
sudo scripts/netns_interop.sh down
```

## How it is tested

| Layer | Oracle | File |
|---|---|---|
| AES, GCM | FIPS-197 App. C, McGrew–Viega GCM test cases, every back-end pair vs. reference on random inputs (also under QEMU) | `tests/test_kat.c` |
| GCM | Project Wycheproof: 197 vectors with 96-bit IVs (valid and forged), all 9 back-end pairs | `tests/test_wycheproof.py` |
| ESP | Scapy's `SecurityAssociation`, both directions, IPv4/IPv6 inner, TCP/UDP/ICMP, 0–1400 B, ESN across 2^32 | `tests/test_esp_interop.py` |
| Replay window | plain-Python model of RFC 4303 3.4.3 driven by randomized reorder/duplicate/jump traffic; ESN inference vs. RFC A2.2 | `tests/test_replay.py` |
| Robustness | every single-bit flip, every truncation, wrong SPI/key/salt, replay/stale, seq overflow, forged packets with valid ICV but bad padding, 5k random packets | `tests/test_negative.py` |
| System | espd ⇄ Linux XFRM and espd ⇄ espd pings at 56/1000/1350 B, ESN, Scapy decrypt of a tcpdump capture | `tests/test_netns.py` |
| Memory safety | ASan + UBSan over the pytest suite; libFuzzer over raw input, round trip and authenticated-trailer modes | `make asan`, `make fuzz` |

Every randomized test is seeded from its test ID, so a failure reproduces exactly (`ESP_SEED` changes the seed).

## Layout

```
include/  aes.h gcm.h replay.h esp.h hwcaps.h
src/      aes.c gcm.c replay.c esp.c ffi.c (handles for ctypes)
tools/    espd.c          TUN <-> ESP tunnel daemon
bench/    espbench.c      single-core and multi-core throughput
tests/    test_kat.c fuzz_decap.c esplib.py (ctypes) test_*.py vectors/
scripts/  netns_interop.sh bench_report.pl
docs/     BENCHMARKS.md WALKTHROUGH.md bench/
```

## Scope and known limits

- Keys are configured by hand (like `ip xfrm state add`); there is no IKEv2 and no SPD/SAD lookup, one SA per direction.
- Outer header is IPv4 (raw socket); inner packets may be IPv4 or IPv6.
- The T-table back-end is not constant-time (table lookups depend on the key); it exists as a portable speed baseline. The hardware back-ends are constant-time.
- Only 96-bit GCM nonces, which is all ESP uses.

## Bugs the tests caught

- **ESN underflow in the RFC pseudocode.** RFC 4303 A2.2 Case B returns `Th - 1`; on a fresh SA (`Th = 0`) that wraps to `0xffffffff`, so the first packets after a jump near 2^32 failed authentication. Fixed with a guard, pinned by `test_esn_fresh_sa_does_not_underflow`.
- **Peer starting at sequence 0.** Scapy's SA sends sequence number 0 by default; RFC 4303 starts at 1 and the receiver correctly rejects 0 as stale. The interop test now configures the peer per the RFC.

## Third-party data

`tests/vectors/aes_gcm_test.json` is from [Project Wycheproof](https://github.com/C2SP/wycheproof) (Apache-2.0).
