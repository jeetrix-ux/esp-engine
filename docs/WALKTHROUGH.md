# Walkthrough: how esp-engine works and how to talk about it

Read this top to bottom once with the code open beside it, then run every command
in "Things to do live". If you can answer the questions at the end without looking,
you own the project.

## 1. Reading order (about 2 hours)

1. `include/esp.h`: the wire format comment and the error list. That is the contract.
2. `src/esp.c`: `esp_encap` then `esp_decap`. Short; everything else exists to serve these two.
3. `src/replay.c`: 60 lines, and the trickiest logic in the repo.
4. `src/gcm.c`: `gcm_seal` → `ctr_xor` + `compute_tag` → `ghash_update` → the three multiplies.
5. `src/aes.c`: the reference path first (mirrors FIPS-197), then T-tables, then hardware.
6. `tests/test_negative.py` and `tests/test_replay.py`: how each guarantee is tested.
7. `tools/espd.c` and `scripts/netns_interop.sh`: how it meets a real network stack.

## 2. The concepts, briefly

**IPsec ESP (RFC 4303).** Encrypts and authenticates IP traffic between two gateways.
A *security association* (SA) is one direction of a tunnel: an SPI (a 32-bit ID the
receiver uses to find the key), a key, and sequence-number state. A tunnel needs two
SAs. *Tunnel mode* encrypts the whole inner IP packet and puts a new outer IP header
in front; next header = 4 (IPv4) or 41 (IPv6). The engine builds only the ESP part;
the kernel adds the outer IPv4 header because espd sends on a raw socket with
protocol 50.

**AES-GCM (SP 800-38D, RFC 4106).** An AEAD: one pass gives confidentiality (AES in
counter mode) and integrity (GHASH, a polynomial MAC over GF(2^128), keyed by
H = AES_K(0)). The 16-byte tag covers the ciphertext *and* the AAD; in ESP the AAD
is the SPI and sequence number, so an attacker cannot move a packet to another SA
or renumber it. RFC 4106 nonce = 4-byte salt (from the key material) || 8-byte IV
(sent in the packet).

**The one rule you must never break with GCM:** never reuse a (key, nonce) pair. Two
messages under the same counter stream XOR to the XOR of their plaintexts, and the
GHASH key H can be recovered, which lets anyone forge tags. The engine uses the
64-bit sequence number as the IV; it is unique per SA by construction, and
`esp_encap` refuses to wrap it (`ESP_ERR_SEQ_OVERFLOW`), which forces a rekey.

**Anti-replay (RFC 4303 3.4.3).** The receiver remembers the highest sequence
number seen (`last`) and a bitmap of the `window` numbers below it. New → accept;
older than the window → stale; inside the window and already set → replay.
Two rules matter:
- check *before* the ICV (so duplicates are cheap to drop),
- update *only after* the ICV verifies (otherwise a forged packet with seq = 10^9
  slides the window and makes all real traffic look stale). `test_forged_packets_do_not_move_window`
  pins this.

**RFC 6479 bitmap.** The naive window shifts a whole bitmap on every new packet.
Here the bitmap is a ring of 64-bit words with one spare word. Advancing just
zeroes the words the window slides onto. Why that is safe: those words hold bits
from `(words-1)*64 = window` numbers back, which are already outside the window.

**ESN (extended sequence numbers).** 32-bit counters wrap after 4 billion packets,
which is about 45 minutes at 10 Gbit/s with small packets. ESN keeps a 64-bit counter
but sends only the low 32 bits; the high 32 bits go into the AAD, so both sides
must agree on them. The receiver infers them from where its window sits (RFC 4303
A2.2). A wrong guess makes the ICV fail, so the guess is self-checking.

## 3. Design decisions (the "why" questions)

| Decision | Why |
|---|---|
| Three back-ends behind one enum | Each faster path is verified against the slow obvious one (differential testing), and the benchmark shows what each optimization buys. |
| Runtime dispatch (CPUID / `getauxval`) instead of compile flags | One binary runs on any x86-64 or AArch64 CPU; functions use `__attribute__((target))` so only they need AES/PCLMUL. |
| IV = sequence number | Unique by construction, no RNG on the fast path. Random IVs would risk birthday collisions after ~2^32 packets. |
| Constant-time tag compare | `memcmp` stops at the first wrong byte; the timing tells an attacker how many tag bytes they got right. |
| Zero the output on auth failure | Callers must never see unauthenticated plaintext ("release of unverified plaintext"). |
| Handle-based FFI (`src/ffi.c`) | Python never mirrors C struct layouts, so changing a struct cannot silently corrupt the tests. |
| One SA per thread in the scaling bench | That is how NICs and DPUs scale (RSS hashes flows to cores): no shared state, no locks. Efficiency drops to 70% at 16 threads because the Core Ultra 9 185H has only 6 P-cores: extra threads land on hyper-thread siblings (which share one core's AES unit) or on slower E-cores. |

## 4. The performance story (be ready to draw this)

Baseline hardware path: 5.94 cycles/byte. Why so slow when AES-NI exists? Each
`AESENC` has ~4 cycles latency but the unit can start one every cycle. Encrypting
one block at a time means 10 rounds × 4 cycles = 40 cycles per 16 bytes with the
unit idle 3/4 of the time. Counter mode blocks are independent, so `ctr_hw` keeps
**8 blocks in flight**: round r of all 8, then round r+1. Now the latency is hidden.

GHASH had the same problem plus a reduction per block. Because multiplication
distributes over XOR,

    ((((Y⊕X0)H ⊕ X1)H ⊕ X2)H ⊕ X3)H  =  (Y⊕X0)·H⁴ ⊕ X1·H³ ⊕ X2·H² ⊕ X3·H

so with H²..H⁴ precomputed, four independent carry-less multiplies can run in
parallel and their 256-bit products are XORed *before* a single reduction
(`ghash_blocks_hw`).

Result: 2.15 cycles/byte, 11.4 Gbit/s per core at 1420 B (2.8x). 64-byte packets
gain only 1.25x: there each packet has a fixed cost (J0 encryption, the length
block, header handling) that bulk optimization does not touch, which is why
packet processors quote Mpps as well as Gbit/s.

## 5. How the GHASH multiply works (the hard part)

GCM stores field elements bit-reflected: the coefficient of x^0 is the MSB of byte 0.
- `mult_ref`: textbook shift-and-add, 128 iterations. Multiply-by-x is a *right*
  shift in this order, and the reduction constant appears as 0xE1 in the top byte.
- `mult_table` (Shoup): precompute i·H for all 16 four-bit values i, then process
  the input a nibble at a time: 32 lookups, each followed by a 4-bit shift whose
  overflow is folded back in through `last4[]`.
- `mult_hw` (x86): byte-swap so each 64-bit lane is an ordinary polynomial, take
  four 64x64 carry-less products (lo, two middles, hi), shift the 256-bit result
  left by 1 (the reflection leaves it off by one bit), and reduce mod
  x^128 + x^7 + x^2 + x + 1 with shifts and XORs.
- AArch64: `RBIT` reverses bits in each byte, which turns GCM order into ordinary
  polynomial order directly (no off-by-one shift). Then fold the top 128 bits down
  twice by multiplying with 0x87 (= x^7 + x^2 + x + 1) using PMULL.

## 6. Test strategy in one paragraph

Every layer has an *independent* oracle: NIST/Wycheproof vectors for the crypto,
Scapy for the packet format, a set-based Python model for the replay window, the
RFC pseudocode for ESN inference, and the Linux kernel for end-to-end behavior.
Negative tests cover each error path, and the sanitizers and fuzzer cover the cases
nobody thought to write down. All randomness is seeded from the test ID so failures
reproduce.

## 7. Questions you should expect, with short answers

1. **Why AES-GCM and not AES-CBC + HMAC?** One pass for both properties, parallel
   (CTR blocks are independent, CBC encryption is serial), no padding-oracle class of
   bugs, and it is what modern IPsec/TLS offload engines implement.
2. **What happens if the IV repeats?** Keystream reuse reveals P1 ⊕ P2, and the
   GHASH key can be solved for, so tags can be forged. Hence seq-as-IV and the overflow refusal.
3. **Why check replay before authenticating and update after?** Before: drop
   duplicates without spending a GCM pass. After: forged packets must not move the window.
4. **Window size trade-off?** Too small: legitimate reordering (multi-path, QoS
   queues, multi-core senders) gets dropped as stale. Larger: more memory per SA. The
   bitmap supports 64 to 4096.
5. **How would you scale this to 100+ Gbit/s?** Shard SAs/flows across cores (done
   in the bench: 129 Gbit/s on 16 threads), batch packets, pre-allocate buffers, and
   offload to inline crypto hardware (what Marvell OCTEON's crypto engines and
   inline IPsec do). The sequence counter is per-SA state: a single fat SA cannot be
   sharded naively across cores without atomics or per-core SAs.
6. **How do you know your AES-NI path is correct?** KAT vectors, Wycheproof, and a
   differential test against the reference on 600 random (key, IV, AAD, length)
   tuples per back-end pair, with lengths up to 700 bytes so the 8-block loop runs
   several times and every tail length is hit.
7. **Why is the T-table AES not constant-time and does it matter?** Lookup indices
   depend on key ⊕ data, so cache timing leaks key bits to a co-located attacker
   (Bernstein 2005). It matters on shared hosts; the hardware path has no tables.
8. **What did the fuzzer actually cover?** Three modes: raw bytes (everything an
   attacker reaches without the key), encap/decap round trips, and authenticated
   packets with fuzzer-chosen trailers (reaches the padding parser behind the ICV).
9. **Describe a bug you found.** The RFC's ESN Case B returns Th - 1 even when Th = 0,
   which underflows on a fresh SA; the interop test failed with an ICV error after the
   transmitter jumped near 2^32. Added a guard and a regression test.
10. **How does the kernel interop test work?** Two network namespaces joined by a
    veth pair. Left: espd on a TUN device. Right: `ip xfrm state/policy` with the
    same keys. A ping from 10.10.0.1 to 10.20.0.1 only gets a reply if both
    implementations agree on every byte. tcpdump captures the wire and Scapy decrypts it too.

## 8. Things to do live (practice until smooth)

```sh
docker run --rm --privileged -v "$PWD:/src" esp-engine-dev make all test
docker run --rm -it --privileged -v "$PWD:/src" esp-engine-dev bash
  scripts/netns_interop.sh up kernel && scripts/netns_interop.sh ping
  ip -n right xfrm state                     # watch oseq/seq advance
  scripts/netns_interop.sh stats
```

Try breaking it on purpose: in `netns_interop.sh`, give the left espd a different
`--key-in` than the key in the kernel's outbound state (for example flip the last
digit of `$KEY_RL` on that line only); the ping fails and `auth_fail` climbs in the
espd stats. Or delete the `th > 0` guard in `replay.c` and watch
`test_esn_fresh_sa_does_not_underflow` fail.
