#!/usr/bin/env bash
# Does the path a secret-handling function takes through its code depend
# on the secret?
#
# `probes/src/bin/constant_flow.rs` runs one operation on one secret.
# This script runs it under an emulator (qemu's user mode) that reports
# every basic block it executes, for eight secrets per operation — all
# zero, all one, the two alternating patterns, four pseudo-random ones —
# and compares the number of blocks: the same number for every secret, or
# the operation's control flow depends on the secret.
#
# The counts are exact, which is what a timing test cannot offer: one
# basic block more shows, on a machine that is doing anything else at the
# same time. They repeat from run to run because nothing but the
# program's own code runs and everything is where it was the last time:
# the probe is linked statically and for a fixed address. (As a
# position-independent executable it is, once in some hundreds of runs,
# loaded somewhere else — the emulator's own image and heap, which the
# host places at random, are in the way — and then its start-up and its
# allocator take a few blocks more or fewer.) And because a dependence on
# the secret repeats exactly, a variation is only reported if it does:
# an operation whose counts differ between secrets is counted again.
# What is covered: the curve
# arithmetic, the symmetric primitives and the AEAD with both keystreams,
# the comparisons at the lengths the protocol uses (16 and 32 bytes), the
# checks of mac1 and mac2, and a whole handshake with a packet each way.
#
# What it cannot see is in the header of the probe: instructions whose
# duration depends on their operands, and secret-dependent addresses.
#
# The check first proves that it can fail: two operations that branch on
# their secret must be reported as varying.
#
# Needs the musl target (`rustup target add <arch>-unknown-linux-musl`)
# and qemu's user-mode emulator for this machine's architecture. Without
# them it says so and exits 0 — unless REQUIRE_QEMU=1 (CI sets it).
set -euo pipefail
cd "$(dirname "$0")/../probes"

arch=$(uname -m)
target="$arch-unknown-linux-musl"
emulator="qemu-$arch"
cannot_run() {
    echo "$1"
    if [ "${REQUIRE_QEMU:-0}" = 1 ]; then
        echo "FAIL: REQUIRE_QEMU=1 and the check could not be run."
        exit 1
    fi
    echo "SKIP: control flow not checked."
    exit 0
}
command -v "$emulator" >/dev/null || cannot_run "No $emulator here (qemu's user-mode emulation)."
rustup target list --installed 2>/dev/null | grep -qx "$target" ||
    cannot_run "The target $target is not installed (rustup target add $target)."

echo "Building the probe for $target..."
cargo rustc --quiet --release --target "$target" --bin constant_flow -- -C relocation-model=static
probe="target/$target/release/constant_flow"

# The emulated CPU: everything the emulator can do, so that the SIMD
# keystream is the vector code where it has one to offer.
blocks() {
    "$emulator" -cpu max -d exec,nochain -D /dev/stdout "$probe" "$@" | grep -c '^Trace' || true
}

secrets="0 1 2 3 4 5 6 7"
# The blocks operation $1 takes, for each secret: its run less a run that
# does nothing.
count() {
    local n base with counts=""
    for n in $secrets; do
        base=$(blocks none "$n")
        with=$(blocks "$1" "$n")
        counts="$counts $((with - base))"
    done
    echo "$counts"
}
how_many_different() {
    tr ' ' '\n' <<<"$1" | grep . | sort -u | wc -l
}

status=0
controls=0
while IFS=$'\t' read -r name what; do
    [ "$name" = none ] && continue
    counts=$(count "$name")
    if [[ $name != control-* ]] && [ "$(how_many_different "$counts")" -gt 1 ]; then
        # Is it the secret? Then the same secrets give the same numbers
        # again. If they do not, a third count decides between the two;
        # three that all differ are no measurement at all.
        again=$(count "$name")
        if [ "$again" != "$counts" ]; then
            third=$(count "$name")
            if [ "$third" != "$again" ] && [ "$third" != "$counts" ]; then
                echo "FAIL: $name: the counts change from run to run ($counts /$again /$third )"
                status=1
                continue
            fi
            echo "  ($name: one count of three was different and is set aside:$counts /$again /$third )"
            counts=$third
        fi
    fi
    distinct=$(tr ' ' '\n' <<<"$counts" | grep -c . || true)
    different=$(how_many_different "$counts")
    first=$(awk '{ print $1 }' <<<"$counts")
    if [ "$distinct" != 8 ] || [ "$first" -le 0 ]; then
        echo "FAIL: $name: could not be counted ($counts )"
        status=1
    elif [[ $name == control-* ]]; then
        if [ "$different" -gt 1 ]; then
            controls=$((controls + 1))
            printf '  %-24s varies, as it must (%s )\n' "$name" "$counts"
        else
            echo "FAIL: $name branches on its secret and was not seen to: this check cannot be trusted."
            exit 2
        fi
    elif [ "$different" = 1 ]; then
        printf '  %-24s %8d blocks, whatever the secret   [%s]\n' "$name" "$first" "$what"
    else
        printf '  %-24s VARIES WITH THE SECRET (%s )   [%s]\n' "$name" "$counts" "$what"
        status=1
    fi
done < <("$probe" list)

if [ "$controls" -lt 2 ]; then
    echo "FAIL: the controls did not run; this check cannot be trusted."
    exit 2
fi
if [ "$status" = 0 ]; then
    echo "PASS: no operation's control flow depends on its secret."
else
    echo "FAIL: see above."
fi
exit "$status"
