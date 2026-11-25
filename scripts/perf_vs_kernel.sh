#!/usr/bin/env bash
# The driver's data path next to the Linux kernel's (and, if you have
# one, wireguard-go's): the same pump against each, on loopback, in a
# network namespace of its own.
#
#   scripts/perf_vs_kernel.sh [seconds]            (default 10)
#
# The pump is bench/src/udp_throughput.rs: one thread that keeps 32
# packets of 1420 bytes in flight through the tunnel and counts the ones
# that come back. What it is pointed at, in turn:
#
#   embed    `udp_throughput echo`: wireguard-embed on one thread, one
#            receive and one send per packet — decrypt, encrypt, back.
#            No TUN device and no IP stack: the driver and its socket.
#   kernel   a `wireguard` interface that forwards what it decrypts back
#            out through itself (the kernel's IP forwarding is the echo),
#            on as many cores as the kernel cares to use
#   go       the same with a wireguard-go interface, if there is a
#            wireguard-go (scripts/build_wireguard_go.sh builds one):
#            its packets also cross a TUN device, twice
#
# The pump is the same in every run, and so is what it costs; what
# differs is the peer. Since the pump is one thread and the kernel is
# not, packets per second say little by themselves (a peer that can do
# more than the pump measures the pump), so with PERF=1 the script also
# counts the cycles of *all* cores during each run — `sudo perf stat -a`,
# on a machine that is doing nothing else — and prints them per echoed
# packet: pump and peer together. Subtract one line from another and the
# pump is gone.
#
#   PERF=1           count cycles system-wide (needs sudo)
#   WINDOW=32        packets the pump keeps in flight
#   PUMP_CPU=4       pin the pump (and ECHO_CPU=5 the embed echo)
#   WIREGUARD_GO=... a wireguard-go binary other than
#                    target/wireguard-go/wireguard-go
#
# Needs: the wireguard kernel module, iproute2, python3, unprivileged
# user namespaces, and a BoringTun checkout next to this repository
# (bench/ does not build without one; see bench/README.md). Not
# wireguard-tools: the interfaces are configured by the helpers the
# interoperability scripts use.
set -euo pipefail
cd "$(dirname "$0")/.."

secs=${1:-10}
# Packets in flight. Fewer than the pump's own default: what the kernel
# sends back is charged to the pump's socket buffer at about twice its
# length, and 64 of those do not fit a buffer of the default size.
window=${WINDOW:-32}
for tool in ip unshare nsenter python3 taskset; do
    command -v "$tool" >/dev/null || { echo "$tool not found"; exit 1; }
done
unshare -Urn true 2>/dev/null || { echo "cannot create a user and network namespace (unshare -Urn)"; exit 1; }

(cd bench && cargo build --release --bin udp_throughput)
cargo build --release --quiet --example pubkey
bin=bench/target/release/udp_throughput

work=$(mktemp -d)
holder=
cleanup() {
    kill $(jobs -p) 2>/dev/null || true
    [ -n "$holder" ] && kill "$holder" 2>/dev/null
    wait 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# Namespaces that stay while this script comes and goes — network, and
# mount for a /var/run of our own, where wireguard-go puts the socket it
# is configured through: a process that holds them, and `ns` to run
# something inside.
mkfifo "$work/ready"
unshare -Urnm sh -c "mount -t tmpfs tmpfs /var/run; echo > '$work/ready'; exec sleep infinity" &
holder=$!
read -r _ <"$work/ready"
ns() { nsenter -t "$holder" -U -n -m --preserve-credentials --wd="$PWD" "$@"; }
# The same for the background (`ns_bg ... &`): the command takes the
# place of the subshell it is started in, so that `$!` is the command.
ns_bg() { exec nsenter -t "$holder" -U -n -m --preserve-credentials --wd="$PWD" "$@"; }

# Keys for this run and no other.
pump_key=$(python3 scripts/wg_netns_helper.py genkey)
peer_key=$(python3 scripts/wg_netns_helper.py genkey)
pump_pub=$(echo "$pump_key" | target/release/examples/pubkey)
peer_pub=$(echo "$peer_key" | target/release/examples/pubkey)

ns ip link set lo up
# The pump's packets are from 10.9.0.2 to 10.9.0.1. Neither address is
# anyone's here: the interface routes both back to the peer they came
# from, which is the echo. (No redirects about that, please: they would
# come back through the tunnel and be counted.)
ns sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward
          echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects
          echo 0 > /proc/sys/net/ipv4/conf/default/send_redirects
          echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
          echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter'

# Run the pump at <port>, with the counters if asked for; print one line.
measure() { # <name> <port>
    local name=$1 port=$2 pps lost cycles= counting=
    if [ "${PERF:-0}" = 1 ]; then
        # The middle of the run: the handshake and the last moments are
        # not part of it.
        (
            sleep 2
            sudo perf stat -a -x, -e cycles:u,cycles:k -o "$work/perf.$name" -- sleep "$((secs - 4))"
        ) &
        counting=$!
    fi
    ns "$(command -v taskset)" -c "${PUMP_CPU:-0-$(($(nproc) - 1))}" \
        "$bin" pump "127.0.0.1:$port" "$pump_key" "$peer_pub" "$secs" "$window" >"$work/pump.$name" 2>&1 ||
        { echo "$name: the pump failed"; cat "$work/pump.$name"; return; }
    [ -z "$counting" ] || wait "$counting" 2>/dev/null || true
    pps=$(sed -nE 's/.*decrypted, ([0-9]+) pps.*/\1/p' "$work/pump.$name")
    lost=$(sed -nE 's/.*\(([0-9.]+)% not echoed.*/\1/p' "$work/pump.$name")
    if [ "${PERF:-0}" = 1 ] && [ -s "$work/perf.$name" ]; then
        cycles=$(awk -F, -v pps="$pps" -v secs="$((secs - 4))" '
            $3 == "cycles:u" { user = $1 } $3 == "cycles:k" { kernel = $1 }
            END { if (pps > 0) printf "%10.0f %10.0f %10.0f", (user + kernel) / pps / secs, user / pps / secs, kernel / pps / secs }' \
            "$work/perf.$name")
    fi
    printf '%-8s %12s %10s %s\n' "$name" "$pps" "$lost" "$cycles"
}

printf '%-8s %12s %10s %10s %10s %10s\n' peer 'echoed/s' 'lost %' 'cycles/pkt' '(user)' '(kernel)'

# ---- wireguard-embed ---------------------------------------------------
ns_bg "$(command -v taskset)" -c "${ECHO_CPU:-0-$(($(nproc) - 1))}" \
    "$bin" echo 51900 "$peer_key" "$pump_pub" >"$work/echo" 2>&1 &
echo_pid=$!
sleep 0.3
measure embed 51900
kill "$echo_pid" 2>/dev/null || true
wait "$echo_pid" 2>/dev/null || true

# ---- the kernel ----------------------------------------------------------
if ns ip link add wgk type wireguard 2>/dev/null; then
    ns python3 scripts/wg_netns_helper.py set wgk --private-key "$peer_key" --listen-port 51901 \
        --peer "$pump_pub" --allowed-ip 10.9.0.0/24
    ns ip link set wgk up
    ns ip route add 10.9.0.0/24 dev wgk
    measure kernel 51901
    ns ip link del wgk
else
    echo "kernel: no wireguard interface to be had here (is the module loaded?)"
fi

# ---- wireguard-go --------------------------------------------------------
# $WIREGUARD_GO, or the one scripts/build_wireguard_go.sh builds.
wireguard_go=${WIREGUARD_GO:-target/wireguard-go/wireguard-go}
if [ -x "$wireguard_go" ]; then
    ns_bg env LOG_LEVEL=error "$wireguard_go" --foreground wgg >"$work/go" 2>&1 &
    go_pid=$!
    uapi() { ns python3 scripts/wg_uapi_helper.py "$@"; }
    up=
    for _ in $(seq 100); do
        if ns test -S /var/run/wireguard/wgg.sock; then
            ns ip link set wgg up 2>/dev/null || true
            # A device that is up has a UDP socket and says so.
            if uapi get wgg 2>/dev/null | grep '^listen_port=' >/dev/null; then
                up=1
                break
            fi
        fi
        sleep 0.05
    done
    if [ -n "$up" ]; then
        uapi set wgg --private-key "$peer_key" --listen-port 51902 \
            --peer "$pump_pub" --allowed-ip 10.9.0.0/24
        ns ip route add 10.9.0.0/24 dev wgg
        measure go 51902
    else
        echo "go: wireguard-go did not bring up an interface:"
        cat "$work/go"
    fi
    kill "$go_pid" 2>/dev/null || true
    wait "$go_pid" 2>/dev/null || true
else
    echo "go: no wireguard-go (scripts/build_wireguard_go.sh builds one, or point WIREGUARD_GO at one)"
fi
