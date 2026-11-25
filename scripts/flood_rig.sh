#!/usr/bin/env bash
# A tunnel that is up, and a flood at the socket it listens on.
#
#   scripts/flood_rig.sh <kind> <threads> <pps-per-thread|0> [seconds]
#
# Three processes on loopback (audit/src/bin/flood.rs): a server running
# the tokio event loop that echoes what it decrypts, its peer pinging
# through the tunnel, and an attacker sending <kind> from <threads>
# threads, each at <pps-per-thread> (0: as fast as it can):
#
#   garbage   40 bytes that are no message at all
#   badmac1   handshake-shaped, wrong mac1          (needs to know nothing)
#   junk4     transport-shaped, 1452 bytes, an index nobody has
#   init      handshake initiations with a valid mac1 (needs the public key)
#   none      no attacker: the baseline
#
# The peer's session is up LEAD seconds before the flood begins; with
# LEAD=0 the flood is there first and the handshake has to get through
# it. Printed at the end: what the attacker sent, what the peer lost and
# how long its packets took, and what the server made of it all.
#
#   LEAD=3                 seconds of quiet first
#   PINGS=2000 PAYLOAD=64  the peer's traffic
#   WG_LIMITER=default     the server's limiter: count:<n>, budget:<ms>,
#                          both:<n>:<ms>, each with ,replies:<per-second>
#   SERVER_CPUS= CLIENT_CPUS= ATTACK_CPUS=
#                          cores for each (taskset lists). Give each its
#                          own, and the attacker a core per thread, or the
#                          result is about the scheduler. On the 16-core
#                          machine the figures in audit/README.md are
#                          from: 8,9 / 10,11 / 12-15,28-31.
#   PERF=1                 also count the server's cycles (sudo perf stat)
set -euo pipefail
cd "$(dirname "$0")/.."

[ "$#" -ge 3 ] || { sed -n '2,32p' "$0"; exit 2; }
kind=$1 threads=$2 pps=$3 secs=${4:-10}
lead=${LEAD:-3} pings=${PINGS:-2000} payload=${PAYLOAD:-64}

(cd audit && cargo build --release --bin flood)
bin=audit/target/release/flood
out=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; wait 2>/dev/null; rm -rf "$out"' EXIT
trap 'exit 130' INT TERM

# For the background only (`on ... &`): the command takes the place of
# the subshell it is started in, so that `$!` is the command and killing
# it leaves nothing behind.
on() { # <cpu list or nothing> <command ...>
    local cpus=$1
    shift
    if [ -n "$cpus" ]; then exec taskset -c "$cpus" "$@"; else exec "$@"; fi
}

port=$((40000 + RANDOM % 20000))
on "${SERVER_CPUS:-}" "$bin" server "$port" >"$out/server" 2>&1 &
server=$!
sleep 0.5

attack() {
    [ "$kind" = none ] && return
    on "${ATTACK_CPUS:-}" "$bin" attack "$port" "$kind" "$threads" "$pps" "$1" >"$out/attack" 2>&1 &
}
if [ "$lead" = 0 ]; then
    attack $((secs + 3))
    sleep 1.5
fi
if [ "${PERF:-0}" = 1 ]; then
    sudo perf stat -e task-clock,cycles:u,cycles:k,instructions:u,instructions:k \
        -p "$server" -o "$out/perf" -- sleep "$((lead + secs))" &
fi
on "${CLIENT_CPUS:-}" "$bin" client "$port" "$pings" "$payload" "$((lead + secs))" >"$out/client" 2>&1 &
client=$!
if [ "$lead" != 0 ]; then
    sleep "$lead"
    attack $((secs + 2))
fi
wait "$client"
sleep 0.3

echo "#### $kind x $threads threads x $pps pps each for ${secs}s, after ${lead}s of quiet; the peer: $pings pps x $payload bytes"
[ "$kind" = none ] || grep -E '^\[atk\]' "$out/attack" | sed -n '2,4p'
grep -E 'time to first|total sent|client loop|\|' "$out/client"
# One second before the flood and three during it.
grep -E "^\[cli +($((lead - 1))|$((lead + 1))|$((lead + secs / 2))|$((lead + secs - 2)))s\]" "$out/client" || true
grep -E "^\[srv +($((lead + secs / 2))|$((lead + secs - 2)))s\]" "$out/server" || true
[ "${PERF:-0}" = 1 ] && grep -E 'task-clock|cycles|instructions' "$out/perf" | sed -E 's/ +/ /g'
exit 0
