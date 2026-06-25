#!/bin/bash
# Interop/conformance driver against the kernel. Run as root inside WSL.
# Exercises wireguard-sans-io against the kernel module in BOTH roles,
# with and without PSK, across the MTU envelope.
set -euo pipefail

BIN="${BIN:-/mnt/c/wg/target/release/examples/interop_conformance}"
test -x "$BIN" || { echo "FAIL: $BIN not found; build with 'cargo build --release --examples'"; exit 1; }

cleanup() {
    ip link del dev wgi 2>/dev/null || true
    ip link del dev wgr 2>/dev/null || true
}
trap cleanup EXIT
cleanup

PASS=0; FAIL=0
result() { if [ "$1" = 0 ]; then PASS=$((PASS+1)); echo "  ✓ $2"; else FAIL=$((FAIL+1)); echo "  ✗ $2"; fi; }

# ============================================================================
# Scenario 1: this impl = INITIATOR, kernel = responder, no PSK
# ============================================================================
echo "=== [1] initiator vs kernel responder (no PSK) ==="
SPRIV=$(wg genkey); SPUB=$(echo "$SPRIV" | wg pubkey)
CPRIV=$(wg genkey); CPUB=$(echo "$CPRIV" | wg pubkey)
ip link add dev wgi type wireguard
ip addr add 10.77.0.1/24 dev wgi
wg set wgi listen-port 51811 private-key <(echo "$SPRIV") peer "$CPUB" allowed-ips 10.77.0.2/32
ip link set up dev wgi
sysctl -qw net.ipv4.icmp_echo_ignore_all=0 || true

"$BIN" initiator 127.0.0.1:51811 "$CPRIV" "$SPUB" 2>&1 | tee /tmp/interop_init.log | grep -E '^\[|PASS' >&2
grep -q INITIATOR_PASS /tmp/interop_init.log; result $? "initiator/no-psk"
ip link del dev wgi

# ============================================================================
# Scenario 2: this impl = INITIATOR, kernel = responder, WITH PSK
# ============================================================================
echo "=== [2] initiator vs kernel responder (PSK) ==="
SPRIV=$(wg genkey); SPUB=$(echo "$SPRIV" | wg pubkey)
CPRIV=$(wg genkey); CPUB=$(echo "$CPRIV" | wg pubkey)
PSK=$(wg genpsk)
ip link add dev wgi type wireguard
ip addr add 10.77.0.1/24 dev wgi
wg set wgi listen-port 51812 private-key <(echo "$SPRIV") \
    peer "$CPUB" allowed-ips 10.77.0.2/32 preshared-key <(echo "$PSK")
ip link set up dev wgi

"$BIN" initiator 127.0.0.1:51812 "$CPRIV" "$SPUB" "$PSK" 2>&1 | tee /tmp/interop_init_psk.log | grep -E '^\[|PASS' >&2
grep -q INITIATOR_PASS /tmp/interop_init_psk.log; result $? "initiator/psk"
ip link del dev wgi

# ============================================================================
# Scenario 3: this impl = RESPONDER, kernel = initiator, no PSK
# ============================================================================
echo "=== [3] responder vs kernel initiator (no PSK) ==="
SPRIV=$(wg genkey); SPUB=$(echo "$SPRIV" | wg pubkey)   # this impl
KPRIV=$(wg genkey); KPUB=$(echo "$KPRIV" | wg pubkey)   # kernel
"$BIN" responder 51813 "$SPRIV" "$KPUB" 2>&1 | tee /tmp/interop_resp.log | grep -E '^\[|PASS' >&2 &
RESP_PID=$!
sleep 0.3
ip link add dev wgr type wireguard
ip addr add 10.77.0.1/24 dev wgr   # kernel = .1, our responder answers as .2
wg set wgr private-key <(echo "$KPRIV") \
    peer "$SPUB" allowed-ips 10.77.0.2/32 endpoint 127.0.0.1:51813
ip link set up dev wgr
ping -c 4 -W 2 -i 0.2 10.77.0.2 >/dev/null 2>&1 || true
wg show wgr | grep -E 'latest handshake|transfer' >&2
wait $RESP_PID 2>/dev/null; RC=$?
grep -q RESPONDER_PASS /tmp/interop_resp.log; result $? "responder/no-psk"
ip link del dev wgr

# ============================================================================
# Scenario 4: this impl = RESPONDER, kernel = initiator, WITH PSK
# ============================================================================
echo "=== [4] responder vs kernel initiator (PSK) ==="
SPRIV=$(wg genkey); SPUB=$(echo "$SPRIV" | wg pubkey)
KPRIV=$(wg genkey); KPUB=$(echo "$KPRIV" | wg pubkey)
PSK=$(wg genpsk)
"$BIN" responder 51814 "$SPRIV" "$KPUB" "$PSK" 2>&1 | tee /tmp/interop_resp_psk.log | grep -E '^\[|PASS' >&2 &
RESP_PID=$!
sleep 0.3
ip link add dev wgr type wireguard
ip addr add 10.77.0.1/24 dev wgr
wg set wgr private-key <(echo "$KPRIV") \
    peer "$SPUB" allowed-ips 10.77.0.2/32 endpoint 127.0.0.1:51814 preshared-key <(echo "$PSK")
ip link set up dev wgr
ping -c 4 -W 2 -i 0.2 10.77.0.2 >/dev/null 2>&1 || true
wait $RESP_PID 2>/dev/null
grep -q RESPONDER_PASS /tmp/interop_resp_psk.log; result $? "responder/psk"
ip link del dev wgr

echo
echo "============================================================"
echo "INTEROP: $PASS passed, $FAIL failed"
echo "============================================================"
[ "$FAIL" = 0 ]
