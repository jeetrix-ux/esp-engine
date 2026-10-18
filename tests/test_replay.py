"""Model-based tests for the anti-replay window: the C bitmap (RFC 6479 ring of
words) is driven with random sequence-number streams and must agree verdict for
verdict with a trivially correct Python model built on a set."""
import pytest

import esplib
from esplib import REPLAY_DUP, REPLAY_OK, REPLAY_STALE


class ModelWindow:
    """RFC 4303 3.4.3 written as plainly as possible."""

    def __init__(self, size):
        self.size, self.last, self.seen = size, 0, set()

    def check(self, seq):
        if seq == 0:
            return REPLAY_STALE
        if seq > self.last:
            return REPLAY_OK
        if self.last - seq >= self.size:
            return REPLAY_STALE
        return REPLAY_DUP if seq in self.seen else REPLAY_OK

    def update(self, seq):
        self.seen.add(seq)
        self.last = max(self.last, seq)
        self.seen = {s for s in self.seen if self.last - s < self.size}


def stream(rng, n, size):
    """Mostly in-order traffic with reordering, duplicates, bursts and big jumps."""
    seq = 0
    for _ in range(n):
        r = rng.random()
        if r < 0.55:
            seq += 1
            yield seq
        elif r < 0.75:
            yield max(0, seq - rng.randrange(0, size + 64))  # late or duplicate
        elif r < 0.9:
            seq += rng.randrange(2, 3 * 64)                    # loss burst
            yield seq
        else:
            seq += rng.randrange(size, 4 * size)               # whole-window jump
            yield seq


@pytest.mark.parametrize("size", [64, 128, 256, 1024, 4096])
def test_matches_model(rng, size):
    dut, model = esplib.ReplayWindow(size), ModelWindow(size)
    for i, seq in enumerate(stream(rng, 6000, size)):
        want = model.check(seq)
        got = dut.check(seq)
        assert got == want, f"step {i}: seq={seq} last={model.last} want={want} got={got}"
        # Only authenticated packets move the window; mimic ~10% forgeries.
        if want == REPLAY_OK and rng.random() > 0.1:
            model.update(seq)
            dut.update(seq)


def test_forged_packets_do_not_move_window():
    """check() must be side-effect free, otherwise an attacker could slide the
    window forward with garbage and make the real traffic look stale."""
    w = esplib.ReplayWindow(64)
    for s in range(1, 11):
        w.update(s)
    for _ in range(100):
        assert w.check(10**6) == REPLAY_OK  # never followed by update()
    assert w.check(5) == REPLAY_DUP
    assert w.check(11) == REPLAY_OK


def test_window_edges():
    w = esplib.ReplayWindow(64)
    w.update(100)
    assert w.check(37) == REPLAY_OK      # 100 - 37 = 63, still inside
    assert w.check(36) == REPLAY_STALE   # 64 behind: off the left edge
    assert w.check(100) == REPLAY_DUP
    assert w.check(0) == REPLAY_STALE


def test_invalid_sizes():
    for bad in (0, 32, 100, 8192):
        with pytest.raises(ValueError):
            esplib.ReplayWindow(bad)


def model_esn_hi(last, size, seq_lo):
    """RFC 4303 Appendix A2.2, plus a guard the RFC lacks: with Th = 0 there is
    no earlier subspace, so Case B must not return Th - 1 (it would wrap)."""
    tl, th = last & 0xFFFFFFFF, last >> 32
    if tl >= size - 1:
        return th if seq_lo >= tl - size + 1 else th + 1
    if seq_lo >= (tl - size + 1) & 0xFFFFFFFF and th > 0:
        return th - 1
    return th


@pytest.mark.parametrize("size", [64, 1024])
def test_esn_inference_matches_rfc(rng, size):
    for _ in range(3000):
        w = esplib.ReplayWindow(size)
        last = rng.choice([rng.randrange(1, 2**40),
                           (rng.randrange(0, 256) << 32) + rng.randrange(0, 2 * size)])
        w.update(last)
        lo = rng.choice([rng.randrange(2**32), (last + rng.randrange(-size, size)) & 0xFFFFFFFF])
        assert w.infer_esn_hi(lo) == model_esn_hi(last, size, lo)


def test_esn_fresh_sa_does_not_underflow():
    """Regression: a brand-new ESN SA (Th = 0) receiving a low word near 2^32
    used to infer Th - 1 = 0xffffffff, per the literal RFC pseudocode."""
    w = esplib.ReplayWindow(128)
    assert w.infer_esn_hi(2**32 - 39) == 0
