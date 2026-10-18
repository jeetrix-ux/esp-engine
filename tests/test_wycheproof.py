"""Project Wycheproof AES-GCM vectors: valid cases must round-trip exactly,
invalid ones (forged tags, edge-case counters) must be rejected."""
import json
import os

import pytest

import esplib

VECTORS = os.path.join(os.path.dirname(__file__), "vectors", "aes_gcm_test.json")


def load():
    """Every vector with a 96-bit IV. ESP always builds its nonce as salt (4) ||
    IV (8), and the engine deliberately supports no other IV length."""
    data = json.load(open(VECTORS))
    return [pytest.param(t, id=f"tc{t['tcId']}")
            for g in data["testGroups"] if g["ivSize"] == 96 for t in g["tests"]]


def test_vector_count():
    assert len(load()) == 197


@pytest.mark.parametrize("tc", load())
def test_vector(tc, impl):
    key, iv, aad = (bytes.fromhex(tc[k]) for k in ("key", "iv", "aad"))
    msg, ct, tag = (bytes.fromhex(tc[k]) for k in ("msg", "ct", "tag"))
    g = esplib.GCM(key, *impl)

    opened = g.open(iv, aad, ct, tag)
    if tc["result"] == "valid":
        assert opened == msg
        got_ct, got_tag = g.seal(iv, aad, msg)
        assert got_ct == ct
        assert got_tag[:len(tag)] == tag
    else:
        assert opened is None, f"accepted invalid vector: {tc['comment']} {tc['flags']}"
