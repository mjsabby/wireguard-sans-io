#!/usr/bin/env bash
# What each kind of datagram costs its receiver, in hardware counters.
#
#   scripts/perf_attack_cost.sh [scenario ...]
#
# Runs audit/src/bin/attack_cost.rs once per scenario and provider under
# `perf stat`, which is told by the program itself when the measured loop
# begins and ends (`--control`), so that set-up — two handshakes, a table
# of datagrams — is not counted. One line per run: nanoseconds, cycles,
# instructions, branch and cache misses, each per datagram.
#
# The scenarios are in the order of what their sender has to know:
# nothing, the public key, something recorded, the keys (the peer
# itself). Without arguments, all of them.
#
#   CPU=4            the core to run on (default: wherever the scheduler puts it)
#   PROVIDERS=...    "scalar simd" (default), or one of them
#   EVENTS=...       perf events; user-space counts by default
#   SCALE=1          multiply the iteration counts (0.1 for a quick look)
#
# Needs perf, and /proc/sys/kernel/perf_event_paranoid of 2 or less
# (counting one's own process in user space needs no more).
set -euo pipefail
cd "$(dirname "$0")/.."

command -v perf >/dev/null || { echo "perf not found"; exit 1; }
(cd audit && cargo build --release --bin attack_cost)
bin=audit/target/release/attack_cost

events="${EVENTS:-cycles:u,instructions:u,branch-misses:u,L1-dcache-load-misses:u,cache-misses:u}"
providers="${PROVIDERS:-scalar simd}"
scale="${SCALE:-1}"

# scenario and how often to run it: cheap ones often, handshakes rarely.
all=(
    garbage:20000000 badmac1:5000000 unknown-index-for:20000000
    unknown-index-routed:10000000 badtag-64:3000000 badtag-1452:1000000
    cookie-check-cold:3000000 cookie-check:2000000 cookie-required:1000000
    init-forged:30000
    resp-forged:15000
    init-replay:30000 replayed:20000000
    encap-64:5000000 encap-1420:1000000 decap-64:3000000 decap-1420:1000000
    handshake-responder:10000 handshake:5000
)
if [ "$#" -gt 0 ]; then
    chosen=()
    for want in "$@"; do
        found=
        for entry in "${all[@]}"; do
            [ "${entry%%:*}" = "$want" ] && { chosen+=("$entry"); found=1; }
        done
        # One not in the list (another length, say): a million times.
        [ -n "$found" ] || chosen+=("$want:1000000")
    done
else
    chosen=("${all[@]}")
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkfifo "$work/ctl" "$work/ack"
exec {ctl}<>"$work/ctl" {ack}<>"$work/ack"

pin=()
[ -n "${CPU:-}" ] && pin=(taskset -c "$CPU")

printf '%-7s %-22s %12s' provider scenario ns
IFS=, read -ra names <<<"$events"
for name in "${names[@]}"; do printf ' %22s' "${name%:u}"; done
echo
for entry in "${chosen[@]}"; do
    scenario="${entry%%:*}"
    iters=$(awk -v n="${entry##*:}" -v s="$scale" 'BEGIN { printf "%d", (n * s < 100) ? 100 : n * s }')
    for provider in $providers; do
        if ! PERF_CTL_FIFO="$work/ctl" PERF_ACK_FIFO="$work/ack" \
            perf stat -D -1 --control "fd:${ctl},${ack}" -e "$events" -x, -o "$work/stat" \
            -- "${pin[@]}" "$bin" "$provider" "$scenario" "$iters" >"$work/out" 2>"$work/err"; then
            cat "$work/err"
            exit 1
        fi
        line=$(grep -m1 '^iters=' "$work/out")
        n=$(sed -E 's/iters=([0-9]+).*/\1/' <<<"$line")
        ns=$(sed -E 's/.*ns_per_op=([0-9.]+).*/\1/' <<<"$line")
        printf '%-7s %-22s %12s' "$provider" "$scenario" "$ns"
        grep -v '^#' "$work/stat" |
            awk -F, -v n="$n" 'NF > 2 && $1 ~ /^[0-9]/ { printf " %22.2f", $1 / n } NF > 2 && $1 !~ /^[0-9]/ { printf " %22s", "-" }'
        echo
    done
done
