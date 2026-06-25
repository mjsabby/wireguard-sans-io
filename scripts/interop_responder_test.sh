#!/bin/bash
set -e

RESP_PRIV='YLTy1nAugleGRLuweRdfzIDPKWEjKgPzjGORbxHSaFA='
RESP_PUB='JAAajN4bWCNGVmn7XI7KW+JmeHvrvKEvuodHYohdrho='
KERN_PRIV='KBzGpc6QlItgkgyzSCCW3kyaEkuV6U0y3Ho19XuL1mU='
KERN_PUB='rKkX+KLnbcSdwFBu0vykzLucxeshnEyCVR2hl/VqikA='

echo "RESP_PRIV=[$RESP_PRIV]"
echo "KERN_PUB=[$KERN_PUB]"

# Start responder in background, listening on localhost.
/tmp/wg/target/release/examples/interop_responder \
    51901 "$RESP_PRIV" "$KERN_PUB" 10.78.0.2 \
    > /tmp/responder.log 2>&1 &
RESP_PID=$!
sleep 0.5

# Configure kernel side to initiate to localhost:51901
ip link del dev wgtest2 2>/dev/null || true
ip link add dev wgtest2 type wireguard
ip addr add 10.78.0.1/24 dev wgtest2
printf '%s\n' "$KERN_PRIV" > /tmp/kpriv
chmod 600 /tmp/kpriv
wg set wgtest2 private-key /tmp/kpriv
wg set wgtest2 peer "$RESP_PUB" allowed-ips 10.78.0.2/32 endpoint 127.0.0.1:51901
ip link set up dev wgtest2

echo "=== kernel config ==="
wg show wgtest2

# Ping triggers kernel to initiate.
echo "=== ping (kernel initiates) ==="
ping -c 3 -W 2 10.78.0.2 2>&1 || true

echo "=== kernel state after ==="
wg show wgtest2

wait $RESP_PID 2>/dev/null || true
echo "=== responder log ==="
cat /tmp/responder.log
echo "=== responder exit code: $? ==="

# Clean up
ip link del dev wgtest2 2>/dev/null || true
