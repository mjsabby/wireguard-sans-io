#!/bin/bash
# Set up a kernel WireGuard interface and print the parameters needed for
# the interop example to connect. Run as root in WSL.
set -euo pipefail

DEV=wgtest
PORT=51899
NET=10.77.0
SERVER_IP=$NET.1
CLIENT_IP=$NET.2

# Clean up any prior run.
ip link del dev $DEV 2>/dev/null || true

# Generate server keys.
SERVER_PRIV=$(wg genkey)
SERVER_PUB=$(echo "$SERVER_PRIV" | wg pubkey)

# Client keys are passed in (so the Rust side can use them).
CLIENT_PRIV="${1:?usage: $0 <client_privkey_b64> [psk_b64]}"
CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
PSK="${2:-}"

# Create and configure the interface.
ip link add dev $DEV type wireguard
ip addr add $SERVER_IP/24 dev $DEV
wg set $DEV listen-port $PORT private-key <(echo "$SERVER_PRIV")
if [ -n "$PSK" ]; then
    wg set $DEV peer "$CLIENT_PUB" allowed-ips $CLIENT_IP/32 preshared-key <(echo "$PSK")
else
    wg set $DEV peer "$CLIENT_PUB" allowed-ips $CLIENT_IP/32
fi
ip link set up dev $DEV

# Allow ICMP from the tunnel.
sysctl -w net.ipv4.icmp_echo_ignore_all=0 >/dev/null 2>&1 || true

# Find the WSL eth0 IP for the Windows side to reach us.
WSL_IP=$(ip -4 addr show eth0 | grep -oP 'inet \K[\d.]+' | head -1)

echo "SERVER_PUB=$SERVER_PUB"
echo "CLIENT_PUB=$CLIENT_PUB"
echo "WSL_IP=$WSL_IP"
echo "PORT=$PORT"
echo "SERVER_TUN_IP=$SERVER_IP"
echo "CLIENT_TUN_IP=$CLIENT_IP"
echo "---"
wg show $DEV
