"""Differential tests against an independent ESP implementation (Scapy's
SecurityAssociation): every packet we build must decrypt there, and every packet
Scapy builds must decrypt here, in tunnel mode, with and without ESN."""
import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.ipsec import ESP, SecurityAssociation
from scapy.packet import Raw

import esplib

OUTER = IP(src="192.0.2.1", dst="198.51.100.1")


def scapy_sa(spi, keymat, esn=False, seq_num=1):
    # seq_num=1: Scapy would otherwise send sequence number 0, which RFC 4303
    # forbids (the counter starts at 1) and our receiver rejects.
    return SecurityAssociation(
        ESP, spi=spi, crypt_algo="AES-GCM", crypt_key=keymat,
        auth_algo="NULL", auth_key=None, tunnel_header=OUTER,
        esn_en=esn, esn=0, seq_num=seq_num)


def on_wire(esp):
    """Wrap raw ESP bytes in an outer IPv4 header (protocol 50) and re-parse,
    so Scapy sees exactly what a peer would receive."""
    return IP(bytes(IP(src=OUTER.src, dst=OUTER.dst, proto=50) / Raw(esp)))


def random_inner(rng):
    body = rng.randbytes(rng.randrange(0, 1400))
    proto = rng.choice([UDP(sport=rng.randrange(1, 65535), dport=53),
                        TCP(sport=rng.randrange(1, 65535), dport=443, flags="PA"),
                        ICMP(type=8, id=rng.randrange(65535))])
    if rng.random() < 0.25:
        return IPv6(src="2001:db8::1", dst="2001:db8::2") / proto / Raw(body), 41
    return IP(src="10.0.0.1", dst="10.0.1.1") / proto / Raw(body), 4


@pytest.mark.parametrize("key_len", [16, 24, 32])
def test_ours_to_scapy(impl, rng, key_len):
    keymat = rng.randbytes(key_len + 4)
    spi = rng.randrange(256, 2**32)
    ours = esplib.SA(spi, keymat, aes=impl[0], ghash=impl[1])
    theirs = scapy_sa(spi, keymat)
    for _ in range(25):
        inner, nh = random_inner(rng)
        esp = ours.encap(bytes(inner), nh)
        decrypted = theirs.decrypt(on_wire(esp))
        assert bytes(decrypted) == bytes(inner)


@pytest.mark.parametrize("key_len", [16, 32])
def test_scapy_to_ours(impl, rng, key_len):
    keymat = rng.randbytes(key_len + 4)
    spi = rng.randrange(256, 2**32)
    ours = esplib.SA(spi, keymat, aes=impl[0], ghash=impl[1])
    theirs = scapy_sa(spi, keymat)
    for _ in range(25):
        inner, nh = random_inner(rng)
        enc = theirs.encrypt(inner)
        payload, got_nh = ours.decap(bytes(enc[ESP]))
        assert payload == bytes(inner)
        assert got_nh == nh


def test_esn_crossing_2_32(rng):
    """Sequence numbers crossing 2^32: the high half is never on the wire, so the
    receiver must infer it (RFC 4303 A2.2) or every ICV after the wrap fails."""
    keymat = rng.randbytes(20)
    tx = esplib.SA(0x1234, keymat, esn=True)
    rx = esplib.SA(0x1234, keymat, esn=True, window=128)
    start = 2**32 - 40
    tx.set_seq(start)
    for i in range(80):
        inner = bytes(IP(dst="10.0.0.9") / UDP() / Raw(bytes([i]) * 20))
        payload, _ = rx.decap(tx.encap(inner))
        assert payload == inner
    assert rx.replay_last == start + 80 > 2**32

    # Scapy agrees on the AAD layout (SPI || seq_hi || seq_lo) for ESN SAs.
    theirs = scapy_sa(0x1234, keymat, esn=True)
    tx2 = esplib.SA(0x1234, keymat, esn=True)
    tx2.set_seq(2**32 + 5 - 1)
    esp = tx2.encap(bytes(IP(dst="10.9.9.9") / ICMP()))
    theirs.esn = 1  # high half the receiver must assume
    assert bytes(theirs.decrypt(on_wire(esp))) == bytes(IP(dst="10.9.9.9") / ICMP())


def test_padding_and_alignment():
    """RFC 4303 2.4: the trailer ends on a 4-byte boundary, pad bytes are 1, 2, 3..."""
    keymat = bytes(range(20))
    tx = esplib.SA(0x1000, keymat)
    rx = esplib.SA(0x1000, keymat)
    for n in range(0, 40):
        esp = tx.encap(b"\xaa" * n, 59)
        ct_len = len(esp) - 8 - 8 - 16
        assert ct_len % 4 == 0 and n + 2 <= ct_len <= n + 5
        assert rx.decap(esp) == (b"\xaa" * n, 59)


def test_sequence_numbers_and_iv_unique():
    keymat = bytes(range(20))
    sa = esplib.SA(0x1000, keymat)
    pkts = [sa.encap(b"x" * 10) for _ in range(500)]
    seqs = [int.from_bytes(p[4:8], "big") for p in pkts]
    assert seqs == list(range(1, 501))
    assert len({p[8:16] for p in pkts}) == 500, "IV reuse under one key breaks GCM"
