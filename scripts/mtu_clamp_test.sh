#!/bin/bash
# Verify this implementation correctly RECEIVES the kernel's MTU-clamped
# (non-16-aligned) transport packets — i.e. the receive path is liberal
# enough that MTU padding only matters on the send side.
set -e
BIN="${BIN:-/tmp/wgbuild/release/examples/interop_conformance}"
ip link del dev wgm 2>/dev/null || true

SPRIV=$(wg genkey); SPUB=$(echo "$SPRIV" | wg pubkey)
KPRIV=$(wg genkey); KPUB=$(echo "$KPRIV" | wg pubkey)

"$BIN" responder 51815 "$SPRIV" "$KPUB" 2>&1 | tee /tmp/mtu.log &
RP=$!
sleep 0.3

ip link add dev wgm type wireguard
ip addr add 10.77.0.1/24 dev wgm
echo "$KPRIV" > /tmp/kpriv; chmod 600 /tmp/kpriv
wg set wgm private-key /tmp/kpriv peer "$SPUB" allowed-ips 10.77.0.2/32 endpoint 127.0.0.1:51815
# MTU 1350: 1350 % 16 = 6, so a 1345..1350-byte inner packet is padded by
# the kernel to exactly 1350 (clamp), NOT 1360. Ciphertext length on the
# wire is then 1350+16 = 1366; total datagram 1382. NOT a multiple of 16.
ip link set mtu 1350 dev wgm
ip link set up dev wgm

# 1322 data + 8 ICMP + 20 IP = 1350 inner = MTU exactly.
ping -c 3 -W 2 -s 1322 10.77.0.2 >/dev/null 2>&1 || true
# 1317 data → 1345 inner: kernel pads to 1350 (clamp), ct=1366, NOT %16.
ping -c 3 -W 2 -s 1317 10.77.0.2 >/dev/null 2>&1 || true

echo "--- kernel transfer ---"
wg show wgm transfer
wait $RP 2>/dev/null || true
ip link del dev wgm

echo "--- responder events ---"
grep -E "data|PASS|FAIL|ERR" /tmp/mtu.log
echo "--- ciphertext lengths seen (should include non-%16 if kernel clamped) ---"
grep -oE 'data [0-9]+B' /tmp/mtu.log | sort | uniq -c
