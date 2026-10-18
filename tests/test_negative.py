"""Negative and robustness tests: every malformed, tampered, replayed or
mis-addressed packet must be rejected with the right error, must leave the SA
usable, and must never crash (run under ASan/UBSan in CI)."""
import pytest

import esplib
from esplib import EspError

KEYMAT = bytes(range(32, 52))
SPI = 0xC0DE


def pair():
    return esplib.SA(SPI, KEYMAT), esplib.SA(SPI, KEYMAT)


def err_of(sa, pkt):
    with pytest.raises(EspError) as e:
        sa.decap(pkt)
    return e.value.name


def test_every_single_bit_flip_is_rejected():
    tx, rx = pair()
    good = tx.encap(b"payload under test" * 3)
    for byte in range(len(good)):
        for bit in range(8):
            bad = bytearray(good)
            bad[byte] ^= 1 << bit
            name = err_of(rx, bytes(bad))
            # SPI bytes fail the SPI lookup, sequence bytes might land on a fresh
            # number but still fail the ICV, everything else fails the ICV.
            assert name in ({"SPI"} if byte < 4 else {"AUTH", "STALE"}), (byte, bit, name)
    assert rx.decap(good)[0] == b"payload under test" * 3
    assert rx.stats["packets"] == 1


@pytest.mark.parametrize("cut", range(0, 34))
def test_truncation(cut):
    tx, rx = pair()
    pkt = tx.encap(b"")  # 36 bytes: the smallest packet possible
    assert len(pkt) == 36
    assert err_of(rx, pkt[:cut]) == "TRUNCATED"


def test_truncated_icv_fails_auth():
    tx, rx = pair()
    pkt = tx.encap(b"A" * 64)
    assert err_of(rx, pkt[:-1]) == "AUTH"


def test_replay_and_stale():
    tx, rx = pair()
    pkts = [tx.encap(bytes([i])) for i in range(200)]
    rx.decap(pkts[0])
    assert err_of(rx, pkts[0]) == "REPLAY"
    rx.decap(pkts[199])
    assert err_of(rx, pkts[1]) == "STALE"       # 198 behind a 64-packet window
    rx.decap(pkts[150])                          # late but inside the window: fine
    assert err_of(rx, pkts[150]) == "REPLAY"
    s = rx.stats
    assert (s["err_replay"], s["err_stale"], s["packets"]) == (2, 1, 3)


def test_wrong_spi_and_wrong_key():
    tx, _ = pair()
    pkt = tx.encap(b"hello")
    assert err_of(esplib.SA(SPI + 1, KEYMAT), pkt) == "SPI"
    assert err_of(esplib.SA(SPI, bytes(20)), pkt) == "AUTH"
    salt_only = KEYMAT[:16] + b"\x00\x00\x00\x00"
    assert err_of(esplib.SA(SPI, salt_only), pkt) == "AUTH"


def test_sequence_overflow_requires_rekey():
    tx, _ = pair()
    tx.set_seq(2**32 - 2)
    tx.encap(b"last-but-one")
    with pytest.raises(EspError) as e:
        tx.encap(b"one too many")
    assert e.value.name == "SEQ_OVERFLOW"


def forge(payload_and_trailer, seq=1):
    """Build an ESP packet with a valid ICV around an arbitrary (possibly
    malformed) plaintext trailer, using the raw GCM layer."""
    g = esplib.GCM(KEYMAT[:16])
    hdr = SPI.to_bytes(4, "big") + seq.to_bytes(4, "big")
    iv = seq.to_bytes(8, "big")
    ct, tag = g.seal(KEYMAT[16:] + iv, hdr, payload_and_trailer)
    return hdr + iv + ct + tag


def test_forge_helper_is_faithful():
    _, rx = pair()
    assert rx.decap(forge(b"ok" + b"\x01\x02" + b"\x02" + b"\x04")) == (b"ok", 4)


def test_bad_pad_length():
    _, rx = pair()
    assert err_of(rx, forge(b"abc" + b"\xff" + b"\x04")) == "PADDING"   # pad_len 255 > data


def test_bad_pad_contents():
    _, rx = pair()
    assert err_of(rx, forge(b"ab" + b"\x09\x09" + b"\x02" + b"\x04")) == "PADDING"
    rx2 = esplib.SA(SPI, KEYMAT)
    rx2.set_check_padding(False)
    assert rx2.decap(forge(b"ab" + b"\x09\x09" + b"\x02" + b"\x04")) == (b"ab", 4)


def test_failed_packet_does_not_advance_window():
    """A packet with a valid ICV but bad padding is still rejected before the
    window moves, so its sequence number stays usable."""
    _, rx = pair()
    with pytest.raises(EspError):
        rx.decap(forge(b"x" + b"\xff" + b"\x04", seq=5))
    assert rx.replay_last == 0
    assert rx.decap(forge(b"ok\x01\x02\x02\x04", seq=5)) == (b"ok", 4)


def test_random_garbage(rng):
    _, rx = pair()
    for _ in range(5000):
        n = rng.randrange(0, 200)
        junk = SPI.to_bytes(4, "big") + rng.randbytes(n) if rng.random() < 0.7 else rng.randbytes(n)
        with pytest.raises(EspError):
            rx.decap(junk)
    assert rx.stats["packets"] == 0


def test_bad_sa_configs():
    for spi, key in [(0, KEYMAT), (255, KEYMAT), (SPI, b"short"), (SPI, bytes(21)), (SPI, bytes(4))]:
        with pytest.raises(ValueError):
            esplib.SA(spi, key)
    with pytest.raises(ValueError):
        esplib.SA(SPI, KEYMAT, window=100)
