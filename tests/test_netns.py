"""End-to-end tunnel tests in network namespaces (Linux, root only).

espd must interoperate with the kernel's own IPsec implementation: pings cross a
tunnel whose two ends are our code and Linux XFRM. The packets captured on the
wire are also decrypted by Scapy, so three independent ESP implementations agree."""
import os
import subprocess
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "netns_interop.sh")
KEY_LR = bytes.fromhex("000102030405060708090a0b0c0d0e0f11223344")

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux") or os.geteuid() != 0,
    reason="needs Linux network namespaces and root")


def sh(*args, **env):
    return subprocess.run([SCRIPT, *args], cwd=ROOT, capture_output=True, text=True,
                          env={**os.environ, **env}, timeout=60)


@pytest.fixture(params=["kernel", "espd"])
def tunnel(request):
    r = sh("up", request.param)
    assert r.returncode == 0, r.stderr
    yield request.param
    sh("down")


@pytest.mark.parametrize("size", [56, 1000, 1350])
def test_ping_through_tunnel(tunnel, size):
    r = sh("ping", COUNT="10", SIZE=str(size))
    assert r.returncode == 0, r.stdout + r.stderr
    assert " 0% packet loss" in r.stdout


@pytest.mark.parametrize("peer", ["kernel"])
def test_esn_with_kernel(peer):
    r = sh("up", peer, ESN="1")
    try:
        assert r.returncode == 0, r.stderr
        r = sh("ping", COUNT="10")
        assert " 0% packet loss" in r.stdout, r.stdout
    finally:
        sh("down")


def test_wire_packets_decrypt_in_scapy():
    from scapy.layers.inet import ICMP, IP
    from scapy.layers.ipsec import ESP, SecurityAssociation
    from scapy.utils import rdpcap

    pcap = "/tmp/esp-netns/wire.pcap"
    assert sh("up", "kernel").returncode == 0
    try:
        cap = subprocess.Popen(["ip", "netns", "exec", "right", "tcpdump", "-U", "-q", "-i", "vr",
                                "-w", pcap, "ip proto 50"], stderr=subprocess.DEVNULL)
        time.sleep(1.5)  # let tcpdump attach before the first packet
        sh("ping", COUNT="5")
        time.sleep(0.5)
        cap.terminate()
        cap.wait()
    finally:
        sh("down")

    sa = SecurityAssociation(ESP, spi=0x1001, crypt_algo="AES-GCM", crypt_key=KEY_LR,
                             auth_algo="NULL", auth_key=None)
    requests = []
    for pkt in rdpcap(pcap):
        if pkt.haslayer(ESP) and pkt[ESP].spi == 0x1001:
            # Without a tunnel_header Scapy hands back outer IP / inner IP / ...
            inner = sa.decrypt(pkt[IP]).getlayer(IP, 2)
            if inner is not None and inner.haslayer(ICMP) and inner[ICMP].type == 8:
                requests.append(inner)
    assert len(requests) == 5
    assert all(p.src == "10.10.0.1" and p.dst == "10.20.0.1" for p in requests)
