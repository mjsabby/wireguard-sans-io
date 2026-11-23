#!/bin/bash
# Verify this implementation correctly RECEIVES the kernel's MTU-clamped
# (non-16-aligned) transport packets — i.e. the receive path is liberal
# enough that MTU padding only matters on the send side.
#
# Run as root. Needs wireguard-tools (`wg`) and `ping`. (The clamped
# padding itself — at the kernel's default MTU of 1420 — is also covered,
# without root, by the size sweep of scripts/interop_netns.sh; this script
# adds an MTU that is far from a multiple of 16.)
#
#   BIN=/path/to/interop_conformance scripts/mtu_clamp_test.sh
set -euo pipefail
BIN="${BIN:-$(cd "$(dirname "$0")/.." && pwd)/target/release/examples/interop_conformance}"
test -x "$BIN" || { echo "FAIL: $BIN not found; build with 'cargo build --release --examples' or set BIN"; exit 1; }

LOG=$(mktemp)
cleanup() { ip link del dev wgm 2>/dev/null || true; rm -f "$LOG" "$LOG.key"; }
trap cleanup EXIT
ip link del dev wgm 2>/dev/null || true

SPRIV=$(wg genkey); SPUB=$(echo "$SPRIV" | wg pubkey)
KPRIV=$(wg genkey); KPUB=$(echo "$KPRIV" | wg pubkey)

"$BIN" responder 51815 "$SPRIV" "$KPUB" >"$LOG" 2>&1 &
RP=$!
sleep 0.3

ip link add dev wgm type wireguard
ip addr add 10.77.0.1/24 dev wgm
( umask 077; echo "$KPRIV" > "$LOG.key" )
wg set wgm private-key "$LOG.key" peer "$SPUB" allowed-ips 10.77.0.2/32 endpoint 127.0.0.1:51815
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
wg show wgm transfer || true
wait $RP 2>/dev/null || true

echo "--- responder events ---"
grep -E "data|PASS|FAIL|ERR" "$LOG" || true
echo "--- ciphertext lengths seen (must include one that is not a multiple of 16) ---"
grep -oE 'data [0-9]+B' "$LOG" | sort | uniq -c || true

# Verdict: the responder's own checks passed, and a clamped packet (1350
# bytes of plaintext) was among what it decrypted.
if grep -q RESPONDER_PASS "$LOG" && grep -qE 'data 1350B' "$LOG"; then
    echo "PASS: the kernel's MTU-clamped packets were received and decrypted."
else
    echo "FAIL: see the log above."
    exit 1
fi
