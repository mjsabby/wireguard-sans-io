#!/usr/bin/env bash
# What a packet costs a receiver that has many peers: with enough of
# them the tunnels do not fit the cache, and a packet's cost is then
# mostly the misses on the way to its tunnel's keys.
#
#   scripts/perf_many_peers.sh [peers ...]      (default: 1 100 10000 100000)
#
# Runs audit/src/bin/many_peers.rs under `perf stat`, counting the
# receive path alone: one packet from every peer per round, the peers in
# a new random order each round. One line per run, figures per packet.
#
#   CPU=4            the core to run on
#   PROVIDER=simd    or scalar
#   PAYLOAD=64       bytes of each packet
#   EVENTS=...       perf events
#
# (100,000 peers take half a gigabyte and a minute to set up.)
set -euo pipefail
cd "$(dirname "$0")/.."

command -v perf >/dev/null || { echo "perf not found"; exit 1; }
(cd audit && cargo build --release --bin many_peers)
bin=audit/target/release/many_peers

events="${EVENTS:-cycles:u,instructions:u,L1-dcache-load-misses:u,cache-misses:u,dTLB-load-misses:u}"
provider="${PROVIDER:-simd}"
payload="${PAYLOAD:-64}"
[ "$#" -gt 0 ] || set -- 1 100 10000 100000

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkfifo "$work/ctl" "$work/ack"
exec {ctl}<>"$work/ctl" {ack}<>"$work/ack"

pin=()
[ -n "${CPU:-}" ] && pin=(taskset -c "$CPU")

printf '%-8s %12s' peers ns
IFS=, read -ra names <<<"$events"
for name in "${names[@]}"; do printf ' %22s' "${name%:u}"; done
echo
for peers in "$@"; do
    # About two million packets in all, and at least four rounds.
    rounds=$((2000000 / peers))
    [ "$rounds" -ge 4 ] || rounds=4
    if ! PERF_CTL_FIFO="$work/ctl" PERF_ACK_FIFO="$work/ack" \
        perf stat -D -1 --control "fd:${ctl},${ack}" -e "$events" -x, -o "$work/stat" \
        -- "${pin[@]}" "$bin" "$provider" "$peers" "$payload" "$rounds" >"$work/out" 2>"$work/err"; then
        cat "$work/err"
        exit 1
    fi
    line=$(grep -m1 '^iters=' "$work/out")
    n=$(sed -E 's/iters=([0-9]+).*/\1/' <<<"$line")
    ns=$(sed -E 's/.*ns_per_op=([0-9.]+).*/\1/' <<<"$line")
    printf '%-8s %12s' "$peers" "$ns"
    grep -v '^#' "$work/stat" |
        awk -F, -v n="$n" 'NF > 2 && $1 ~ /^[0-9]/ { printf " %22.2f", $1 / n } NF > 2 && $1 !~ /^[0-9]/ { printf " %22s", "-" }'
    echo
done
