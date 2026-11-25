#!/usr/bin/env bash
# Interop/conformance against wireguard-go, the reference userspace
# implementation: the scenarios of scripts/interop_netns.sh, with a
# wireguard-go device where that script has the kernel's interface. No root
# and no wireguard-tools here either: everything runs inside private
# namespaces, the device is configured over its UAPI socket by
# scripts/wg_uapi_helper.py, and this implementation is the
# `interop_conformance` example talking to it over loopback.
#
#   scripts/build_wireguard_go.sh          # once: target/wireguard-go/wireguard-go
#   scripts/interop_wireguard_go.sh        # all scenarios (2 minutes)
#   scripts/interop_wireguard_go.sh quick  # skip the two 35 s timer scenarios (45 s)
#
# Needs:
#   * a wireguard-go binary: $WIREGUARD_GO, or the one on PATH, or the one
#     scripts/build_wireguard_go.sh builds. With none the script says so
#     and exits 0 — or 1 if REQUIRE_WIREGUARD_GO=1 is set.
#   * iproute2, python3, util-linux (unshare, setpriv), /dev/net/tun, and
#     a way into namespaces of its own: unprivileged user namespaces
#     (`unshare -Ur...`) or passwordless sudo (`sudo unshare ...`). Without
#     one the script says so and exits 0 — or 1 if REQUIRE_NETNS=1 is set.
#     As in scripts/interop_netns.sh: a check that silently does nothing
#     is not a check.
#
# Scenarios:
#   1/2  we initiate, wireguard-go responds (no PSK / PSK): handshake +
#        ICMP echo at every interesting size
#   3/4  wireguard-go initiates, we respond (no PSK / PSK)
#   5    wireguard-go initiates while we are "under load": the cookie dance
#   6    crossed handshakes: both sides initiate at once. What wireguard-go
#        makes of that varies from run to run (see crossed_scenario); a
#        session has to be there at once and no ping lost. (One run in
#        forty or so meets a fault of wireguard-go's there, which its log
#        shows; that run is not counted and the scenario is repeated.)
#   7    one-way stream FROM wireguard-go for 35 s: we must send a
#        keepalive every 10 s and wireguard-go must not re-handshake
#   8    one-way stream TO wireguard-go for 35 s: wireguard-go sends
#        keepalives and we must not re-handshake
#
# A scenario passes on our side's verdict, as in interop_netns.sh, and on
# the other end's, which that script shows or throws away: what our side
# sent has to have come out of wireguard-go's interface — the echo
# replies, and every datagram of the stream — and what went into it out
# of the tunnel at our end.
set -euo pipefail
# The script re-executes itself inside the namespaces, after changing
# directory: by its absolute path, so that it can be started from
# anywhere and by any name.
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
started_in=$PWD
cd "$(dirname "$SELF")/.."

# What wireguard-go needs where it runs: /var/run/wireguard for its UAPI
# socket, and a TUN device.
#
# The first is a tmpfs over /var/run, in a mount namespace of our own:
# nobody else sees it, an unprivileged user could not write to the real
# one, and root (the sudo way in) leaves nothing in it.
private_var_run() { mount -t tmpfs tmpfs /var/run; }

if [ "${1:-}" = "--probe" ]; then
    # Inside the namespaces, before anything is built on them: can a TUN
    # device be made here? (TUNSETIFF, for a device that goes when this
    # process does.)
    private_var_run
    exec python3 -I -c '
import fcntl, os, struct, sys
TUNSETIFF, IFF_TUN, IFF_NO_PI = 0x400454CA, 0x0001, 0x1000
try:
    tun = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(tun, TUNSETIFF, struct.pack("16sH22x", b"wgprobe", IFF_TUN | IFF_NO_PI))
except OSError as error:
    sys.exit("no TUN device: %s" % error)
'
fi

if [ "${1:-}" != "--inside" ]; then
    # wireguard-go: $WIREGUARD_GO (that or nothing), the one on PATH, the
    # one scripts/build_wireguard_go.sh builds. $WIREGUARD_GO can be a
    # command on PATH or a path, and the path one relative to where the
    # script was started.
    if [ -n "${WIREGUARD_GO:-}" ]; then
        wireguard_go=$(cd "$started_in" && command -v "$WIREGUARD_GO" || true)
        case "$wireguard_go" in
            /* | "") ;;
            *) wireguard_go="$started_in/$wireguard_go" ;;
        esac
        if ! [ -x "$wireguard_go" ]; then
            echo "FAIL: \$WIREGUARD_GO is '$WIREGUARD_GO', and that is not an executable."
            exit 1
        fi
    elif command -v wireguard-go >/dev/null 2>&1; then
        wireguard_go=$(command -v wireguard-go)
    elif [ -x target/wireguard-go/wireguard-go ]; then
        wireguard_go="$PWD/target/wireguard-go/wireguard-go"
    else
        echo "No wireguard-go: scripts/build_wireguard_go.sh builds one, or point WIREGUARD_GO at one."
        if [ "${REQUIRE_WIREGUARD_GO:-0}" = 1 ]; then
            echo "FAIL: REQUIRE_WIREGUARD_GO=1 and the interop scenarios could not be run."
            exit 1
        fi
        echo "SKIP: interop scenarios not run."
        exit 0
    fi

    cargo build --release --quiet --example interop_conformance --example pubkey

    # Namespaces of our own: network (the device, and loopback to reach
    # it), mount (see private_var_run) and PID. The last is for what the
    # other two cannot do. wireguard-go is a daemon: a script that is
    # killed before it can stop it leaves it running, and its interface
    # and both namespaces with it. In a PID namespace nothing outlives
    # the namespace's first process — when that one goes, the kernel kills
    # the rest — and the first process here is one that does nothing but
    # wait for the script to go: the script's death, of whatever, is
    # SIGKILL to it (`setpriv --pdeathsig`).
    #
    # (`unshare --pid` moves the children of the process it runs into the
    # new namespace and not that process, so the script stays where it
    # is, with its PID, and gets its signals as it always did. It could
    # be the first process itself — `--fork` — but that one gets only the
    # signals it has handlers for, and from an `unshare` that blocks
    # SIGINT and SIGTERM.)
    namespaces=(-nm --pid)
    # shellcheck disable=SC2016  # for the `sh -c` below to expand
    first='setpriv --pdeathsig KILL sleep infinity & exec "$0" "$@"'
    # Two ways in, as in interop_netns.sh: unprivileged user namespaces,
    # or — where those are restricted but sudo is passwordless (hosted CI
    # runners) — the same namespaces as root. The binaries are built
    # above, as the invoking user.
    mode="${1:-all}"
    why_not=""
    # enter <command...>: with it into the namespaces and on with the
    # scenarios there, if wireguard-go can have what it needs there;
    # otherwise back, with what the attempt said.
    enter() {
        local said
        if said=$("$@" "${namespaces[@]}" sh -c "$first" "$SELF" --probe 2>&1); then
            exec "$@" "${namespaces[@]}" sh -c "$first" "$SELF" --inside "$mode" "$wireguard_go"
        fi
        why_not+="  $* ${namespaces[*]}:"$'\n'"$(sed 's/^/      /' <<<"$said")"$'\n'
    }
    enter unshare -Ur
    enter sudo -n unshare
    echo "Cannot give wireguard-go namespaces of its own with a tmpfs over /var/run and a TUN device here:"
    printf '%s' "$why_not"
    if [ "${REQUIRE_NETNS:-0}" = 1 ]; then
        echo "FAIL: REQUIRE_NETNS=1 and the interop scenarios could not be run."
        exit 1
    fi
    echo "SKIP: interop scenarios not run."
    exit 0
fi
MODE="$2"
WIREGUARD_GO="$3"

BIN=target/release/examples/interop_conformance
PUBKEY=target/release/examples/pubkey
WG="python3 scripts/wg_netns_helper.py"     # keys and traffic: the parts of it that are not about the kernel
UAPI="python3 scripts/wg_uapi_helper.py"    # wireguard-go's configuration

private_var_run
ip link set lo up
# The logs go on the tmpfs too: gone with the namespace, however the
# script ends.
LOG=$(mktemp -d -p /var/run)
genkey() { $WG genkey; }
pubkey() { echo "$1" | "$PUBKEY"; }

PASS=0; FAIL=0
result() {
    if [ "$1" = 0 ]; then PASS=$((PASS+1)); echo "  ✓ $2"; else FAIL=$((FAIL+1)); echo "  ✗ $2"; fi
}
# The example was written against the kernel and calls its peer that;
# here the peer is wireguard-go, and the lines shown say so.
show_log() {
    grep -E '^\[=\]|^\[\+\] (handshake|cookie)|FAIL|panicked' "$1" |
        sed 's/the kernel/wireguard-go/g; s/kernel/wireguard-go/g; s/^/      /' || true
}
# wireguard-go's own account (LOG_LEVEL=verbose), without its banner and
# the comings and goings of its worker routines.
go_log() { grep -E '^(DEBUG|ERROR): ' "$LOG/wireguard-go" | grep -v 'Routine: ' || true; }
# From that, what it says about the protocol: the handshake messages and
# keepalives it sent and received, what it rejected, its timers — in the
# order it happened, a line that repeats shown once with its count. (It
# does not log data packets.) Everything but what is known to be about
# something else, so that the unexpected shows.
show_go_log() {
    go_log | grep -v -E 'UAPI| - (Starting|Stopping)$|Interface |UDP bind|Device (started|closing|closed)|MTU updated|Starting wireguard-go|Shutting down' |
        sed -E 's/^DEBUG: \(wggo\) [0-9/]+ [0-9:]+ //; s/^(ERROR): \(wggo\) [0-9/]+ [0-9:]+ /\1: /; s/peer\([^)]*\) - //' |
        uniq -c | sed -E 's/^ *1 (.*)/      wireguard-go: \1/; s/^ *([0-9]+) (.*)/      wireguard-go: \2 (×\1)/' || true
}
# What the programs at wireguard-go's end of the tunnel — the helper's
# ping, udp-stream and udp-sink, on its interface — have to say.
show_far_end() { sed "s/^/      wireguard-go's end: /" "$1"; }
# count <file> <text>: the number that follows the text, on the line of
# the file that begins with it. Nothing, if there is no such line.
count() { sed -n "s/^$2\([0-9][0-9]*\).*/\1/p" "$1"; }

# scenario <label> <function> [args...]
#
# Runs one scenario and counts its verdict: the exit status of the
# function, whose last command looks for the PASS marker in the log. A
# scenario that fails — the marker is missing, or one of its commands
# fails — is a failed scenario; the ones after it still run, and the
# summary at the end has them all. (The function runs in a subshell under
# `set -e`, outside any `if` or `||`, which is where `set -e` works.)
#
# Every scenario gets a wireguard-go of its own. It is started here, not
# in the function: as a child of this shell, which can wait until it is
# gone again — and with it its interface and its socket, whose names the
# next one takes.
#
# One verdict is neither a pass nor a failure: PEER_FAULT, which a
# scenario returns when its own side did everything asked of it and what
# went wrong is a fault of wireguard-go's that its log identifies (so
# far there is one: see crossed_scenario). Such a run says nothing about
# this implementation, so the scenario is run again — three times at the
# most, each time said out loud and counted in the summary. A scenario
# that meets the fault three times in a row fails: that is no longer the
# one run in forty it was when this was written.
PEER_FAULT=75
REPEATS=0
scenario() {
    local label="$1" status attempt; shift
    for attempt in 1 2 3; do
        LOG_LEVEL=verbose "$WIREGUARD_GO" --foreground wggo >"$LOG/wireguard-go" 2>&1 &
        GO_PID=$!
        set +e
        ( set -e; "$@" )
        status=$?
        set -e
        go_down
        [ "$status" = "$PEER_FAULT" ] || break
        REPEATS=$((REPEATS+1))
        if [ "$attempt" -lt 3 ]; then
            echo "  ↻ $label: not counted — wireguard-go's fault, not a verdict on this implementation. Once more."
        fi
    done
    result "$status" "$label"
}
# Inside a scenario: stop the process under test when the scenario ends,
# however it ends.
stop_at_exit() { trap "kill $1 2>/dev/null || true" EXIT; }

# go_wait <what is missing> <command...>: until the command succeeds; a
# failed scenario, with wireguard-go's account, if it has not within 5 s.
go_wait() {
    local missing="$1" tries=0; shift
    until "$@"; do
        tries=$((tries+1))
        if [ "$tries" -gt 100 ]; then
            echo "      wireguard-go: $missing after 5 s. It says:"
            go_log | sed 's/^/      /'
            return 1
        fi
        sleep 0.05
    done
}
go_has_socket() { [ -S /var/run/wireguard/wggo.sock ]; }
# A device that is up has a UDP socket, and says which port it is on.
# (Not `grep -q`: that would leave the helper writing into a closed pipe.)
go_is_up() { $UAPI get wggo 2>/dev/null | grep '^listen_port=' >/dev/null; }

# go_up <listen-port|-> <wireguard-go-priv> <peer-pub> [extra uapi args...]
go_up() {
    local port="$1" priv="$2" peer="$3"; shift 3
    go_wait "no UAPI socket" go_has_socket
    ip addr add 10.77.0.1/24 dev wggo
    ip link set up dev wggo
    # Configured only now, as a device that is up: `set` then returns
    # with the device listening on its port and the peer started, and
    # nothing that a scenario sends next is lost. (A device that is not
    # up yet takes its configuration too, but acts on it whenever it
    # learns that its interface is up — a moment after it is.)
    go_wait "no UDP socket" go_is_up
    if [ "$port" = "-" ]; then
        $UAPI set wggo --private-key "$priv" --peer "$peer" --allowed-ip 10.77.0.2/32 "$@"
    else
        $UAPI set wggo --private-key "$priv" --listen-port "$port" --peer "$peer" \
            --allowed-ip 10.77.0.2/32 "$@"
    fi
}
# Stop wireguard-go and wait until it is gone: it closes its device and
# removes its socket on SIGTERM. One that does not within 5 s is killed.
go_down() {
    local tries=0
    [ -n "$GO_PID" ] || return 0
    kill "$GO_PID" 2>/dev/null || true
    while kill -0 "$GO_PID" 2>/dev/null; do
        tries=$((tries+1))
        if [ "$tries" -gt 100 ]; then kill -9 "$GO_PID" 2>/dev/null || true; break; fi
        sleep 0.05
    done
    wait "$GO_PID" 2>/dev/null || true
    GO_PID=""
}
GO_PID=""
trap go_down EXIT

# ---------------------------------------------------------------------------
initiator_scenario() {   # <name> <port> [psk]
    local name="$1" port="$2" psk="${3:-}"
    echo "=== we initiate, wireguard-go responds ($name) ==="
    local gpriv; gpriv=$(genkey); local gpub; gpub=$(pubkey "$gpriv")
    local opriv; opriv=$(genkey); local opub; opub=$(pubkey "$opriv")
    if [ -n "$psk" ]; then
        go_up "$port" "$gpriv" "$opub" --psk "$psk"
        "$BIN" initiator "127.0.0.1:$port" "$opriv" "$gpub" "$psk" >"$LOG/$name" 2>&1 || true
    else
        go_up "$port" "$gpriv" "$opub"
        "$BIN" initiator "127.0.0.1:$port" "$opriv" "$gpub" >"$LOG/$name" 2>&1 || true
    fi
    show_log "$LOG/$name"
    show_go_log
    grep -q INITIATOR_PASS "$LOG/$name"
}

responder_scenario() {   # <name> <role> <port> [psk]
    local name="$1" role="$2" port="$3" psk="${4:-}"
    echo "=== wireguard-go initiates, we respond ($name) ==="
    local gpriv; gpriv=$(genkey); local gpub; gpub=$(pubkey "$gpriv")
    local opriv; opriv=$(genkey); local opub; opub=$(pubkey "$opriv")
    if [ -n "$psk" ]; then
        "$BIN" "$role" "$port" "$opriv" "$gpub" "$psk" >"$LOG/$name" 2>&1 &
    else
        "$BIN" "$role" "$port" "$opriv" "$gpub" >"$LOG/$name" 2>&1 &
    fi
    local pid=$!
    stop_at_exit "$pid"
    sleep 0.3
    if [ -n "$psk" ]; then
        go_up - "$gpriv" "$opub" --endpoint "127.0.0.1:$port" --psk "$psk"
    else
        go_up - "$gpriv" "$opub" --endpoint "127.0.0.1:$port"
    fi
    # A ping of our inner address goes into wireguard-go's interface; our
    # side answers each echo. With the cookie dance wireguard-go only
    # retries after Rekey-Timeout (5 s).
    $WG ping 10.77.0.2 12 1 >"$LOG/$name.ping" 2>&1 || true
    wait "$pid" 2>/dev/null || true
    show_log "$LOG/$name"
    show_go_log
    show_far_end "$LOG/$name.ping"
    # Our side's verdict — and the other direction's: our side answers
    # three echoes and stops, and those three have to have come out of
    # wireguard-go's interface.
    local replies; replies=$(count "$LOG/$name.ping" 'ping: ')
    grep -q RESPONDER_PASS "$LOG/$name"
    [ "${replies:-0}" -ge 3 ]
}

sink_scenario() {
    echo "=== one-way stream FROM wireguard-go, 35 s ==="
    local gpriv; gpriv=$(genkey); local gpub; gpub=$(pubkey "$gpriv")
    local opriv; opriv=$(genkey); local opub; opub=$(pubkey "$opriv")
    "$BIN" sink 37 51816 "$opriv" "$gpub" >"$LOG/sink" 2>&1 &
    local pid=$!
    stop_at_exit "$pid"
    sleep 0.3
    go_up - "$gpriv" "$opub" --endpoint 127.0.0.1:51816
    $WG udp-stream 10.77.0.2 9999 35 0.1 >"$LOG/sink.stream"
    wait "$pid" 2>/dev/null || true
    show_log "$LOG/sink"
    show_go_log
    show_far_end "$LOG/sink.stream"
    # Our side's verdict — and nothing lost: every datagram that went
    # into wireguard-go's interface came out of the tunnel at our end.
    local sent received
    sent=$(count "$LOG/sink.stream" 'udp-stream: sent ')
    received=$(count "$LOG/sink" '\[=\] sink: ')
    grep -q SINK_PASS "$LOG/sink"
    [ -n "$sent" ] && [ "$sent" = "$received" ]
}

source_scenario() {
    echo "=== one-way stream TO wireguard-go, 35 s ==="
    local gpriv; gpriv=$(genkey); local gpub; gpub=$(pubkey "$gpriv")
    local opriv; opriv=$(genkey); local opub; opub=$(pubkey "$opriv")
    go_up 51817 "$gpriv" "$opub"
    # Something to swallow our datagrams, so that nothing has a reason to
    # answer with ICMP port-unreachable — and to count them.
    $WG udp-sink 10.77.0.1 9999 38 >"$LOG/source.sink" &
    local sink=$!
    stop_at_exit "$sink"
    sleep 0.3
    "$BIN" source 35 127.0.0.1:51817 "$opriv" "$gpub" >"$LOG/source" 2>&1 || true
    wait "$sink" 2>/dev/null || true
    show_log "$LOG/source"
    show_go_log
    show_far_end "$LOG/source.sink"
    # Our side's verdict — and nothing lost: every datagram our side sent
    # came out of wireguard-go's interface.
    local sent received
    sent=$(count "$LOG/source" '\[=\] source: sent ')
    received=$(count "$LOG/source.sink" 'udp-sink: received ')
    grep -q SOURCE_PASS "$LOG/source"
    [ -n "$sent" ] && [ "$sent" = "$received" ]
}

crossed_scenario() {
    echo "=== both sides initiate at once (crossed handshakes) ==="
    local gpriv; gpriv=$(genkey); local gpub; gpub=$(pubkey "$gpriv")
    local opriv; opriv=$(genkey); local opub; opub=$(pubkey "$opriv")
    # `crossed-either`, not the `crossed` of interop_netns.sh. The kernel
    # answers our initiation and drops its own, every time. wireguard-go
    # has a handshake worker per CPU, and two of them take our initiation
    # and our answer to its own at once; what it does is whatever that
    # race comes to. In its log, below:
    #
    #   1. "Received invalid response message": it answered ours and
    #      rejected our answer to its own, as the kernel does. Mostly.
    #   2. "Failed to create response message: handshake initiation must
    #      be consumed first": it took our answer, completed its own
    #      handshake and could then not answer ours.
    #   3. "Received handshake response" and then "Received handshake
    #      initiation": it took our answer, and then answered ours too.
    #   4. the same two lines the other way round: it answered ours, and
    #      then took our answer too.
    #
    # In 1 to 3 a session is there at once and no ping is lost, whichever
    # handshake it is of; that is what the role asserts, and it says which
    # completed. 4 is a fault of wireguard-go's (0.0.20250522): it then
    # sends on the session of its own initiation and accepts nothing on
    # it. If that is the session our side settles on — the newest one,
    # as the protocol has it, and as the kernel would — what we send is
    # dropped until wireguard-go has heard nothing for 15 s and starts
    # again. (When this was written: 4 in 12 of 600 runs — on 2, 4 and 32
    # CPUs alike — and our side on that session in 7 of the 12, all of
    # them on 2 or 4 CPUs.)
    #
    # The fault, in device/noise-protocol.go: ConsumeMessageResponse
    # checks that the handshake is still waiting for a response while it
    # holds the handshake's lock for reading, lets go of it, and takes it
    # again for writing to record the response — without looking again.
    # In between, the worker with our initiation can have consumed it,
    # answered it (CreateMessageResponse deletes the index wireguard-go's
    # own initiation went out with) and begun the session (which sets the
    # handshake's index to zero). The response is then recorded all the
    # same, and the session begun from it has index zero: wireguard-go
    # sends on it, and what comes back, addressed to the index it sent in
    # its initiation, finds nobody.
    #
    # Such a run has not shown anything about this implementation — its
    # own checks passed, and the pings were lost inside wireguard-go — so
    # it is not counted either way: the scenario returns PEER_FAULT and
    # is run again (see scenario). Only this, and only when wireguard-go's
    # own log shows that order of events; our side's verdict is asked for
    # first and is never excused.
    "$BIN" crossed-either 51818 127.0.0.1:51819 "$opriv" "$gpub" >"$LOG/crossed" 2>&1 &
    local pid=$!
    stop_at_exit "$pid"
    sleep 0.3
    go_up 51819 "$gpriv" "$opub" --endpoint 127.0.0.1:51818
    # The first ping makes wireguard-go initiate; our side holds that
    # initiation back until its own is on the wire. The pings are answered
    # as soon as there is a session.
    $WG ping 10.77.0.2 5 1 >"$LOG/crossed.ping" 2>&1 || true
    wait "$pid" 2>/dev/null || true
    show_log "$LOG/crossed"
    show_go_log
    show_far_end "$LOG/crossed.ping"
    # As in responder_scenario: three echoes answered, three received.
    local replies; replies=$(count "$LOG/crossed.ping" 'ping: ')
    grep -q CROSSED_PASS "$LOG/crossed"
    if [ "${replies:-0}" -lt 3 ] && go_log | awk '
            /^ERROR/ { error = 1 }
            /Received handshake initiation$/ { answered_ours = 1 }
            /Received handshake response$/ { if (answered_ours) then_took_our_answer = 1 }
            END { exit !(then_took_our_answer && !error) }'; then
        echo "      (wireguard-go answered our initiation, then took our answer to its own, and since then accepts"
        echo "       nothing on the session it sends on: a fault of wireguard-go's, 4 in the comment in crossed_scenario.)"
        return "$PEER_FAULT"
    fi
    [ "${replies:-0}" -ge 3 ]
}

scenario "initiator/no-psk" initiator_scenario no-psk 51811
scenario "initiator/psk"    initiator_scenario psk 51812 "$(genkey)"
scenario "responder/no-psk" responder_scenario no-psk responder 51813
scenario "responder/psk"    responder_scenario psk responder 51814 "$(genkey)"
scenario "responder/cookie" responder_scenario cookie responder-cookie 51815
scenario "crossed handshakes" crossed_scenario
if [ "$MODE" != "quick" ]; then
    scenario "one-way stream from wireguard-go" sink_scenario
    scenario "one-way stream to wireguard-go" source_scenario
fi

echo
echo "============================================================"
echo "INTEROP vs $("$WIREGUARD_GO" --version | sed -n 1p): $PASS passed, $FAIL failed"
if [ "$REPEATS" != 0 ]; then
    echo "($REPEATS run(s) not counted and repeated: wireguard-go's crossed-handshake fault)"
fi
echo "============================================================"
[ "$FAIL" = 0 ]
