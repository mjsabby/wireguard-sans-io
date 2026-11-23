#!/usr/bin/env bash
# Interop/conformance against the Linux kernel's WireGuard — without root
# and without wireguard-tools. Everything runs inside a private user +
# network namespace: the kernel side is a real `wireguard` interface
# configured over netlink by scripts/wg_netns_helper.py, and this
# implementation is the `interop_conformance` example talking to it over
# loopback.
#
#   scripts/interop_netns.sh            # all scenarios (~95 s)
#   scripts/interop_netns.sh quick      # skip the two 35 s timer scenarios
#
# Needs: the wireguard kernel module, iproute2, python3, and a way into a
# network namespace: unprivileged user namespaces (`unshare -Urn`) or
# passwordless sudo (`sudo unshare -n`). Without one the script says so and
# exits 0 — or 1 if REQUIRE_NETNS=1 is set, as CI does: a check that
# silently does nothing is not a check.
#
# Scenarios:
#   1/2  we initiate, kernel responds (no PSK / PSK): handshake + ICMP echo
#        at every interesting size
#   3/4  kernel initiates, we respond (no PSK / PSK)
#   5    kernel initiates while we are "under load": the cookie dance
#   6    one-way stream FROM the kernel for 35 s: we must send a keepalive
#        every 10 s and the kernel must not re-handshake
#   7    one-way stream TO the kernel for 35 s: the kernel sends keepalives
#        and we must not re-handshake
#   8    crossed handshakes: both sides initiate at once; the kernel
#        answers ours and drops its own, we answer the kernel's and keep
#        ours, and ours completes in one round trip
set -euo pipefail
# The script re-executes itself inside the namespace, after changing
# directory: by its absolute path, so that it can be started from
# anywhere and by any name.
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
cd "$(dirname "$SELF")/.."

if [ "${1:-}" != "--inside" ]; then
    cargo build --release --quiet --example interop_conformance --example pubkey
    # Two ways into a namespace of our own, as in driver_netns_tests.sh:
    # unprivileged user namespaces, or — where those are restricted but
    # sudo is passwordless (hosted CI runners) — a network namespace as
    # root. The binaries are built above, as the invoking user.
    if unshare -Urn true 2>/dev/null; then
        exec unshare -Urn "$SELF" --inside "${1:-all}"
    elif sudo -n true 2>/dev/null && sudo -n unshare -n true 2>/dev/null; then
        exec sudo -n unshare -n "$SELF" --inside "${1:-all}"
    fi
    echo "Cannot create a network namespace here (tried 'unshare -Urn' and 'sudo unshare -n')."
    if [ "${REQUIRE_NETNS:-0}" = 1 ]; then
        echo "FAIL: REQUIRE_NETNS=1 and the interop scenarios could not be run."
        exit 1
    fi
    echo "SKIP: interop scenarios not run."
    exit 0
fi
MODE="$2"

BIN=target/release/examples/interop_conformance
PUBKEY=target/release/examples/pubkey
WG="python3 scripts/wg_netns_helper.py"
LOG=$(mktemp -d)
trap 'rm -rf "$LOG"' EXIT

ip link set lo up
genkey() { $WG genkey; }
pubkey() { echo "$1" | "$PUBKEY"; }

PASS=0; FAIL=0
result() {
    if [ "$1" = 0 ]; then PASS=$((PASS+1)); echo "  ✓ $2"; else FAIL=$((FAIL+1)); echo "  ✗ $2"; fi
}
show_log() { grep -E '^\[=\]|^\[\+\] (handshake|cookie)|FAIL|panicked' "$1" | sed 's/^/      /' || true; }

# scenario <label> <function> [args...]
#
# Runs one scenario and counts its verdict: the exit status of the
# function, whose last command looks for the PASS marker in the log. A
# scenario that fails — the marker is missing, or one of its commands
# fails — is a failed scenario; the ones after it still run, and the
# summary at the end has them all. (The function runs in a subshell under
# `set -e`, outside any `if` or `||`, which is where `set -e` works.)
scenario() {
    local label="$1" status; shift
    set +e
    ( set -e; "$@" )
    status=$?
    set -e
    kernel_down
    result "$status" "$label"
}
# Inside a scenario: stop the process under test when the scenario ends,
# however it ends.
stop_at_exit() { trap "kill $1 2>/dev/null || true" EXIT; }

# kernel_up <listen-port|-> <kernel-priv> <peer-pub> [extra wg args...]
kernel_up() {
    local port="$1" priv="$2" peer="$3"; shift 3
    ip link add dev wgk type wireguard
    ip addr add 10.77.0.1/24 dev wgk
    if [ "$port" = "-" ]; then
        $WG set wgk --private-key "$priv" --peer "$peer" --allowed-ip 10.77.0.2/32 "$@"
    else
        $WG set wgk --private-key "$priv" --listen-port "$port" --peer "$peer" \
            --allowed-ip 10.77.0.2/32 "$@"
    fi
    ip link set up dev wgk
}
kernel_down() { ip link del dev wgk 2>/dev/null || true; }

# ---------------------------------------------------------------------------
initiator_scenario() {   # <name> <port> [psk]
    local name="$1" port="$2" psk="${3:-}"
    echo "=== we initiate, kernel responds ($name) ==="
    local kpriv; kpriv=$(genkey); local kpub; kpub=$(pubkey "$kpriv")
    local opriv; opriv=$(genkey); local opub; opub=$(pubkey "$opriv")
    if [ -n "$psk" ]; then
        kernel_up "$port" "$kpriv" "$opub" --psk "$psk"
        "$BIN" initiator "127.0.0.1:$port" "$opriv" "$kpub" "$psk" >"$LOG/$name" 2>&1 || true
    else
        kernel_up "$port" "$kpriv" "$opub"
        "$BIN" initiator "127.0.0.1:$port" "$opriv" "$kpub" >"$LOG/$name" 2>&1 || true
    fi
    show_log "$LOG/$name"
    grep -q INITIATOR_PASS "$LOG/$name"
}

responder_scenario() {   # <name> <role> <port> [psk]
    local name="$1" role="$2" port="$3" psk="${4:-}"
    echo "=== kernel initiates, we respond ($name) ==="
    local kpriv; kpriv=$(genkey); local kpub; kpub=$(pubkey "$kpriv")
    local opriv; opriv=$(genkey); local opub; opub=$(pubkey "$opriv")
    if [ -n "$psk" ]; then
        "$BIN" "$role" "$port" "$opriv" "$kpub" "$psk" >"$LOG/$name" 2>&1 &
    else
        "$BIN" "$role" "$port" "$opriv" "$kpub" >"$LOG/$name" 2>&1 &
    fi
    local pid=$!
    stop_at_exit "$pid"
    sleep 0.3
    if [ -n "$psk" ]; then
        kernel_up - "$kpriv" "$opub" --endpoint "127.0.0.1:$port" --psk "$psk"
    else
        kernel_up - "$kpriv" "$opub" --endpoint "127.0.0.1:$port"
    fi
    # The kernel pings our inner address; our side answers each echo. With
    # the cookie dance the kernel only retries after Rekey-Timeout (5 s).
    $WG ping 10.77.0.2 12 1 >"$LOG/$name.ping" 2>&1 || true
    wait "$pid" 2>/dev/null || true
    show_log "$LOG/$name"
    sed 's/^/      kernel /' "$LOG/$name.ping"
    grep -q RESPONDER_PASS "$LOG/$name"
}

sink_scenario() {
    echo "=== one-way stream FROM the kernel, 35 s ==="
    local kpriv; kpriv=$(genkey); local kpub; kpub=$(pubkey "$kpriv")
    local opriv; opriv=$(genkey); local opub; opub=$(pubkey "$opriv")
    "$BIN" sink 37 51816 "$opriv" "$kpub" >"$LOG/sink" 2>&1 &
    local pid=$!
    stop_at_exit "$pid"
    sleep 0.3
    kernel_up - "$kpriv" "$opub" --endpoint 127.0.0.1:51816
    $WG udp-stream 10.77.0.2 9999 35 0.1 >/dev/null
    wait "$pid" 2>/dev/null || true
    show_log "$LOG/sink"
    grep -q SINK_PASS "$LOG/sink"
}

source_scenario() {
    echo "=== one-way stream TO the kernel, 35 s ==="
    local kpriv; kpriv=$(genkey); local kpub; kpub=$(pubkey "$kpriv")
    local opriv; opriv=$(genkey); local opub; opub=$(pubkey "$opriv")
    kernel_up 51817 "$kpriv" "$opub"
    # Something to swallow our datagrams, so the kernel has no reason to
    # answer with ICMP port-unreachable.
    $WG udp-sink 10.77.0.1 9999 38 >/dev/null &
    local sink=$!
    stop_at_exit "$sink"
    sleep 0.3
    "$BIN" source 35 127.0.0.1:51817 "$opriv" "$kpub" >"$LOG/source" 2>&1 || true
    wait "$sink" 2>/dev/null || true
    show_log "$LOG/source"
    grep -q SOURCE_PASS "$LOG/source"
}

crossed_scenario() {
    echo "=== both sides initiate at once (crossed handshakes) ==="
    local kpriv; kpriv=$(genkey); local kpub; kpub=$(pubkey "$kpriv")
    local opriv; opriv=$(genkey); local opub; opub=$(pubkey "$opriv")
    "$BIN" crossed 51818 127.0.0.1:51819 "$opriv" "$kpub" >"$LOG/crossed" 2>&1 &
    local pid=$!
    stop_at_exit "$pid"
    sleep 0.3
    kernel_up 51819 "$kpriv" "$opub" --endpoint 127.0.0.1:51818
    # The first ping makes the kernel initiate; our side holds that
    # initiation back until its own is on the wire. The pings are answered
    # as soon as our handshake has completed.
    $WG ping 10.77.0.2 5 1 >"$LOG/crossed.ping" 2>&1 || true
    wait "$pid" 2>/dev/null || true
    show_log "$LOG/crossed"
    sed 's/^/      kernel /' "$LOG/crossed.ping"
    grep -q CROSSED_PASS "$LOG/crossed"
}

scenario "initiator/no-psk" initiator_scenario no-psk 51811
scenario "initiator/psk"    initiator_scenario psk 51812 "$(genkey)"
scenario "responder/no-psk" responder_scenario no-psk responder 51813
scenario "responder/psk"    responder_scenario psk responder 51814 "$(genkey)"
scenario "responder/cookie" responder_scenario cookie responder-cookie 51815
scenario "crossed handshakes" crossed_scenario
if [ "$MODE" != "quick" ]; then
    scenario "one-way stream from the kernel" sink_scenario
    scenario "one-way stream to the kernel" source_scenario
fi

echo
echo "============================================================"
echo "INTEROP vs kernel $(uname -r): $PASS passed, $FAIL failed"
echo "============================================================"
[ "$FAIL" = 0 ]
