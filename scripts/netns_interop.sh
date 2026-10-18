#!/usr/bin/env bash
# Two network namespaces joined by a veth "wire":
#
#   ns left   (10.10.0.1)  espd, tun esp0      192.168.100.1 ──┐
#                                                              │ veth, ESP (IP proto 50)
#   ns right  (10.20.0.1)  PEER                192.168.100.2 ──┘
#
# PEER=kernel: the right side is the Linux kernel's IPsec stack (ip xfrm), so
#              espd has to produce packets the kernel accepts, and vice versa.
# PEER=espd:   the right side is a second espd.
#
# usage: sudo scripts/netns_interop.sh up [kernel|espd] | ping | down
set -euo pipefail

ESPD=${ESPD:-build/native/espd}
# RFC 4106 KEYMAT = 16-byte AES key || 4-byte salt, one per direction
KEY_LR=${KEY_LR:-0x000102030405060708090a0b0c0d0e0f11223344}
KEY_RL=${KEY_RL:-0xf0e0d0c0b0a090807060504030201000aabbccdd}
SPI_LR=0x00001001
SPI_RL=0x00002002
ESN=${ESN:-0}
RUN=${RUN:-/tmp/esp-netns}

esn_args() { [[ $ESN == 1 ]] && echo "--esn" || true; }

up() {
    local peer=${1:-kernel}
    down 2>/dev/null || true
    mkdir -p "$RUN"
    ip netns add left
    ip netns add right
    ip link add vl type veth peer name vr
    ip link set vl netns left
    ip link set vr netns right
    ip -n left addr add 192.168.100.1/24 dev vl
    ip -n right addr add 192.168.100.2/24 dev vr
    for ns in left right; do
        ip -n $ns link set lo up
    done
    ip -n left link set vl up
    ip -n right link set vr up

    # left: espd owns 10.10.0.0/24 <-> 10.20.0.0/24
    ip netns exec left "$ESPD" --tun esp0 --peer 192.168.100.2 \
        --spi-out $SPI_LR --key-out $KEY_LR --spi-in $SPI_RL --key-in $KEY_RL \
        $(esn_args) </dev/null >/dev/null 2>"$RUN/espd-left.log" &
    echo $! >"$RUN/espd-left.pid"
    for _ in $(seq 50); do ip -n left link show esp0 &>/dev/null && break; sleep 0.1; done
    ip -n left addr add 10.10.0.1/24 dev esp0
    ip -n left link set esp0 up mtu 1400
    ip -n left route add 10.20.0.0/24 dev esp0 src 10.10.0.1

    if [[ $peer == kernel ]]; then
        local esn_flag=""
        [[ $ESN == 1 ]] && esn_flag="flag esn replay-window 64"
        ip -n right addr add 10.20.0.1/32 dev lo
        ip -n right xfrm state add src 192.168.100.1 dst 192.168.100.2 proto esp spi $SPI_LR \
            mode tunnel aead 'rfc4106(gcm(aes))' $KEY_LR 128 replay-window 64 $esn_flag
        ip -n right xfrm state add src 192.168.100.2 dst 192.168.100.1 proto esp spi $SPI_RL \
            mode tunnel aead 'rfc4106(gcm(aes))' $KEY_RL 128 $esn_flag
        ip -n right xfrm policy add src 10.20.0.0/24 dst 10.10.0.0/24 dir out \
            tmpl src 192.168.100.2 dst 192.168.100.1 proto esp mode tunnel
        ip -n right xfrm policy add src 10.10.0.0/24 dst 10.20.0.0/24 dir in \
            tmpl src 192.168.100.1 dst 192.168.100.2 proto esp mode tunnel
        ip -n right route add 10.10.0.0/24 via 192.168.100.1 src 10.20.0.1
    else
        ip netns exec right "$ESPD" --tun esp0 --peer 192.168.100.1 \
            --spi-out $SPI_RL --key-out $KEY_RL --spi-in $SPI_LR --key-in $KEY_LR \
            $(esn_args) </dev/null >/dev/null 2>"$RUN/espd-right.log" &
        echo $! >"$RUN/espd-right.pid"
        for _ in $(seq 50); do ip -n right link show esp0 &>/dev/null && break; sleep 0.1; done
        ip -n right addr add 10.20.0.1/24 dev esp0
        ip -n right link set esp0 up mtu 1400
        ip -n right route add 10.10.0.0/24 dev esp0 src 10.20.0.1
    fi
}

ping_test() {
    ip netns exec left ping -c "${COUNT:-5}" -i 0.05 -W 2 -s "${SIZE:-56}" -I 10.10.0.1 10.20.0.1
}

stats() {
    for f in "$RUN"/espd-*.pid; do kill -USR1 "$(cat "$f")" 2>/dev/null || true; done
    sleep 0.6
    cat "$RUN"/espd-*.log
    ip -n right xfrm state 2>/dev/null | grep -E "spi|anti-replay" || true
    ip netns exec right cat /proc/net/xfrm_stat 2>/dev/null | awk '$2 != 0' || true
}

down() {
    for f in "$RUN"/espd-*.pid; do [[ -f $f ]] && kill "$(cat "$f")" 2>/dev/null; rm -f "$f"; done
    ip netns del left 2>/dev/null || true
    ip netns del right 2>/dev/null || true
}

case ${1:-} in
up) up "${2:-kernel}" ;;
ping) ping_test ;;
stats) stats ;;
down) down ;;
*) echo "usage: $0 up [kernel|espd] | ping | stats | down" >&2; exit 2 ;;
esac
