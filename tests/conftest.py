import os
import random
import sys
import zlib

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import esplib  # noqa: E402

# ESP_IMPLS=table,hw restricts the run (the sanitizer job skips the slow
# bitwise reference; test_kat still covers it under ASan).
IMPLS = [i for i in esplib.impls()
         if esplib.IMPL_NAMES[i] in os.environ.get("ESP_IMPLS", "ref,table,hw").split(",")]
IMPL_PAIRS = [(a, g) for a in IMPLS for g in IMPLS]


def pair_id(p):
    return f"aes={esplib.IMPL_NAMES[p[0]]}-ghash={esplib.IMPL_NAMES[p[1]]}"


@pytest.fixture(params=IMPL_PAIRS, ids=pair_id)
def impl(request):
    """Run the test once for every (AES, GHASH) implementation pair this CPU has."""
    return request.param


@pytest.fixture
def rng(request):
    # Seeded per test so a failure always reproduces; override with ESP_SEED.
    seed = int(os.environ.get("ESP_SEED", "0")) ^ zlib.crc32(request.node.nodeid.encode())
    return random.Random(seed)


def pytest_report_header(config):
    return f"libesp hardware crypto path: {'available' if esplib.hw_available() else 'not available'}"
