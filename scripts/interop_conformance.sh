#!/bin/bash
# Interop/conformance driver against the kernel, for a host where the
# example binary is built elsewhere (for instance on Windows, and run from
# WSL). Run as root. Needs wireguard-tools (`wg`) and `ping`.
# Exercises wireguard-sans-io against the kernel module in BOTH roles,
# with and without PSK, across the MTU envelope.
#
# scripts/interop_netns.sh runs the same scenarios and more (cookies,
# crossed handshakes, one-way streams) without root and without
# wireguard-tools; it is the one CI runs. Prefer it where it can run.
#
#   BIN=/path/to/interop_conformance scripts/interop_conformance.sh
set -euo pipefail

BIN="${BIN:-$(cd "$(dirname "$0")/.." && pwd)/target/release/examples/interop_conformance}"
test -x "$BIN" || { echo "FAIL: $BIN not found; build with 'cargo build --release --examples' or set BIN"; exit 1; }

LOGS=$(mktemp -d)
cleanup() {
    ip link del dev wgi 2>/dev/null || true
    ip link del dev wgr 2>/dev/null || true
}
trap 'cleanup; rm -rf "$LOGS"' EXIT
cleanup

PASS=0; FAIL=0
result() { if [ "$1" = 0 ]; then PASS=$((PASS+1)); echo "  ✓ $2"; else FAIL=$((FAIL+1)); echo "  ✗ $2"; fi; }
# verdict <marker> <log> <label>: the scenario passed if its log has the
# marker. (As an `if`, so that a missing marker is a failed scenario and
# not — under `set -e` — the end of the script before any summary.)
verdict() { if grep -q "$1" "$2"; then result 0 "$3"; else result 1 "$3"; fi; }
# Show the interesting lines of a log; having none is not an error.
show() { grep -E '^\[|PASS' "$1" >&2 || true; }

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

"$BIN" initiator 127.0.0.1:51811 "$CPRIV" "$SPUB" >"$LOGS/init.log" 2>&1 || true
show "$LOGS/init.log"
verdict INITIATOR_PASS "$LOGS/init.log" "initiator/no-psk"
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

"$BIN" initiator 127.0.0.1:51812 "$CPRIV" "$SPUB" "$PSK" >"$LOGS/init_psk.log" 2>&1 || true
show "$LOGS/init_psk.log"
verdict INITIATOR_PASS "$LOGS/init_psk.log" "initiator/psk"
ip link del dev wgi

# ============================================================================
# Scenario 3: this impl = RESPONDER, kernel = initiator, no PSK
# ============================================================================
echo "=== [3] responder vs kernel initiator (no PSK) ==="
SPRIV=$(wg genkey); SPUB=$(echo "$SPRIV" | wg pubkey)   # this impl
KPRIV=$(wg genkey); KPUB=$(echo "$KPRIV" | wg pubkey)   # kernel
"$BIN" responder 51813 "$SPRIV" "$KPUB" >"$LOGS/resp.log" 2>&1 &
RESP_PID=$!
sleep 0.3
ip link add dev wgr type wireguard
ip addr add 10.77.0.1/24 dev wgr   # kernel = .1, our responder answers as .2
wg set wgr private-key <(echo "$KPRIV") \
    peer "$SPUB" allowed-ips 10.77.0.2/32 endpoint 127.0.0.1:51813
ip link set up dev wgr
ping -c 4 -W 2 -i 0.2 10.77.0.2 >/dev/null 2>&1 || true
wg show wgr | grep -E 'latest handshake|transfer' >&2 || true
wait $RESP_PID 2>/dev/null || true
show "$LOGS/resp.log"
verdict RESPONDER_PASS "$LOGS/resp.log" "responder/no-psk"
ip link del dev wgr

# ============================================================================
# Scenario 4: this impl = RESPONDER, kernel = initiator, WITH PSK
# ============================================================================
echo "=== [4] responder vs kernel initiator (PSK) ==="
SPRIV=$(wg genkey); SPUB=$(echo "$SPRIV" | wg pubkey)
KPRIV=$(wg genkey); KPUB=$(echo "$KPRIV" | wg pubkey)
PSK=$(wg genpsk)
"$BIN" responder 51814 "$SPRIV" "$KPUB" "$PSK" >"$LOGS/resp_psk.log" 2>&1 &
RESP_PID=$!
sleep 0.3
ip link add dev wgr type wireguard
ip addr add 10.77.0.1/24 dev wgr
wg set wgr private-key <(echo "$KPRIV") \
    peer "$SPUB" allowed-ips 10.77.0.2/32 endpoint 127.0.0.1:51814 preshared-key <(echo "$PSK")
ip link set up dev wgr
ping -c 4 -W 2 -i 0.2 10.77.0.2 >/dev/null 2>&1 || true
wait $RESP_PID 2>/dev/null || true
show "$LOGS/resp_psk.log"
verdict RESPONDER_PASS "$LOGS/resp_psk.log" "responder/psk"
ip link del dev wgr

echo
echo "============================================================"
echo "INTEROP: $PASS passed, $FAIL failed"
echo "============================================================"
[ "$FAIL" = 0 ]
