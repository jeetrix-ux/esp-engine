# Benchmarks

_espbench: 22 online cores, hardware crypto yes_

## Single core

| op | back-end | payload (B) | Mpps | Gbit/s | cycles/byte | vs ref |
|---|---|---:|---:|---:|---:|---:|
| decap | ref | 64 | 0.086 | 0.04 | 560.23 | 1.0x |
| decap | table | 64 | 1.655 | 0.85 | 29.00 | 19.2x |
| decap | hw | 64 | 5.418 | 2.77 | 8.86 | 63.0x |
| decap | ref | 512 | 0.016 | 0.07 | 363.71 | 1.0x |
| decap | table | 512 | 0.309 | 1.27 | 19.41 | 18.6x |
| decap | hw | 512 | 2.438 | 9.99 | 2.46 | 146.9x |
| decap | ref | 1420 | 0.006 | 0.07 | 358.18 | 1.0x |
| decap | table | 1420 | 0.119 | 1.35 | 18.25 | 19.5x |
| decap | hw | 1420 | 0.979 | 11.12 | 2.21 | 161.1x |
| encap | ref | 64 | 0.086 | 0.04 | 560.82 | 1.0x |
| encap | table | 64 | 1.611 | 0.82 | 29.79 | 18.8x |
| encap | hw | 64 | 5.885 | 3.01 | 8.16 | 68.5x |
| encap | ref | 512 | 0.016 | 0.07 | 367.08 | 1.0x |
| encap | table | 512 | 0.314 | 1.29 | 19.10 | 19.2x |
| encap | hw | 512 | 2.378 | 9.74 | 2.52 | 145.4x |
| encap | ref | 1420 | 0.006 | 0.07 | 353.27 | 1.0x |
| encap | table | 1420 | 0.121 | 1.37 | 17.91 | 19.6x |
| encap | hw | 1420 | 1.008 | 11.45 | 2.15 | 163.6x |

## Multi-core encap scaling (hw, 1420-byte payload, one SA per thread)

| threads | Gbit/s | speed-up | efficiency |
|---:|---:|---:|---:|
| 1 | 11.55 | 1.00x | 100% |
| 2 | 22.89 | 1.98x | 99% |
| 4 | 44.70 | 3.87x | 97% |
| 8 | 82.46 | 7.14x | 89% |
| 16 | 129.39 | 11.20x | 70% |

## Optimisation history (hw back-end, single core)

| step | change | 1420 B encap | cycles/byte | 64 B encap |
|---|---|---:|---:|---:|
| opt0-single-block | one AES block and one GHASH reduction at a time | 4.14 Gbit/s | 5.94 | 4.72 Mpps |
| opt1-interleaved | 8 AES-NI blocks in flight + 4-block aggregated GHASH (H..H^4) | 11.45 Gbit/s | 2.15 | 5.89 Mpps |

Measured in Docker Desktop (WSL2, Linux 6.6) on an Intel Core Ultra 9 185H laptop (6 P-cores with hyper-threading + 10 E-cores, 22 threads). Cycles are TSC ticks, which run at a fixed reference clock, not the boosted core clock. Raw output is in `docs/bench/`.
