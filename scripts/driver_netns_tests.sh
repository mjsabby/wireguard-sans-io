#!/usr/bin/env bash
# Driver tests that need a namespace of their own:
#
#   * forged ICMP errors against the async event loop — one at a time, and
#     by the thousand (embed/tests/icmp_errors.rs). Forging ICMP takes a
#     raw socket; inside a network namespace of our own we have that
#     capability without being root on the host, and nothing we send
#     leaves the namespace.
#   * the driver's clock (embed/src/clock.rs): that it is the clock which
#     counts time spent suspended. On a machine that has never been
#     suspended that clock and the ordinary one read the same, so the test
#     runs in a time namespace where it is a day ahead.
#
# The test binaries are built as the invoking user; only the binaries
# themselves run inside the namespaces. Two ways in are tried:
#
#   unshare -Ur...    unprivileged user namespaces (most distributions)
#   sudo unshare ...  where those are restricted but sudo is passwordless
#                     (hosted CI runners)
#
# If neither works the script says so and exits 0 — unless REQUIRE_NETNS=1
# is set (CI sets it), in which case not being able to run is a failure:
# a check that silently does nothing is not a check.
set -euo pipefail
cd "$(dirname "$0")/.."

cannot_run() {
    echo "$1"
    if [ "${REQUIRE_NETNS:-0}" = 1 ]; then
        echo "FAIL: REQUIRE_NETNS=1 and the tests could not be run."
        exit 1
    fi
    echo "SKIP: $2"
}

# The executable cargo builds for one test target of wireguard-embed.
test_binary() { # <cargo arguments selecting the target> <target name>
    local name="${!#}"
    cargo test -p wireguard-embed --features async "${@:1:$#-1}" --no-run --message-format=json 2>/dev/null |
        python3 -I -c '
import json, sys
for line in sys.stdin:
    try:
        message = json.loads(line)
    except ValueError:
        continue
    if message.get("reason") == "compiler-artifact" and message.get("executable") and message["target"]["name"] == sys.argv[1]:
        print(message["executable"])
' "$name"
}

echo "Building the test binaries..."
icmp=$(test_binary --test icmp_errors icmp_errors)
unit=$(test_binary --lib wireguard_embed)
for binary in "$icmp" "$unit"; do
    if [ -z "$binary" ] || [ ! -x "$binary" ]; then
        echo "FAIL: could not build the driver's test binaries."
        exit 1
    fi
done

# ---- forged ICMP errors: a network namespace --------------------------------
if unshare -Urn true 2>/dev/null; then
    enter=(unshare -Urn)
elif sudo -n true 2>/dev/null && sudo -n unshare -n true 2>/dev/null; then
    enter=(sudo -n unshare -n)
else
    enter=()
    cannot_run "Cannot create a network namespace here (tried 'unshare -Urn' and 'sudo unshare -n')." \
        "forged-ICMP tests not run."
fi
if [ ${#enter[@]} -gt 0 ]; then
    echo "Forged ICMP errors, inside a private network namespace (${enter[*]})..."
    "${enter[@]}" sh -c 'ip link set lo up && exec "$0" --ignored --test-threads=1' "$icmp"
    echo "PASS: forged ICMP errors neither end the event loop, nor deafen its socket, nor cost it its sends."
fi

# ---- the clock: a time namespace --------------------------------------------
ahead=86400
if unshare -Ur --time --boottime "$ahead" true 2>/dev/null; then
    enter=(unshare -Ur --time --boottime "$ahead")
elif sudo -n true 2>/dev/null && sudo -n unshare --time --boottime "$ahead" true 2>/dev/null; then
    enter=(sudo -n unshare --time --boottime "$ahead")
else
    enter=()
    cannot_run "Cannot create a time namespace here (tried 'unshare -Ur --time --boottime' with and without sudo)." \
        "the clock test was not run where it can tell the two clocks apart."
fi
if [ ${#enter[@]} -gt 0 ]; then
    echo "The driver's clock, inside a time namespace whose boot-time clock is a day ahead (${enter[*]})..."
    out=$("${enter[@]}" env WG_BOOT_TIME_AHEAD_SECS="$ahead" "$unit" --exact \
        clock::tests::the_clock_is_the_one_that_counts_suspend --nocapture 2>&1) || {
        echo "$out"
        echo "FAIL: the driver's clock is not the one that counts time spent suspended."
        exit 1
    }
    # The test must have run, and must have seen the offset: a filter that
    # matches nothing also "passes".
    if ! grep -q "boot-time clock $ahead s ahead of CLOCK_MONOTONIC, as arranged" <<<"$out"; then
        echo "$out"
        echo "FAIL: the clock test did not run, or did not see the namespace's offset."
        exit 1
    fi
    echo "PASS: the driver's clock counts time spent suspended."
fi
