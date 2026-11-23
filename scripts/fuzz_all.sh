#!/usr/bin/env bash
# Run every libFuzzer target for a bounded time (default 120s each).
# Requires: a nightly toolchain (the one called `nightly`, or the one
# named in NIGHTLY — CI pins a date) and cargo-fuzz.
#
#   scripts/fuzz_all.sh [seconds-per-target] [extra libfuzzer args...]
#
# Each target starts from two corpora: `fuzz/corpus/<target>` (this
# machine's, grown by every run, not checked in) and `fuzz/seeds/<target>`
# (checked in, read-only here): a small set of inputs that between them
# reach every code edge long runs have reached, so that even a short run —
# CI's — starts from deep protocol states instead of from nothing.
#
# To refresh the seeds after the targets or the protocol code changed, fuzz
# for a while and then, per target:
#
#   rm -r fuzz/seeds/<target> && mkdir fuzz/seeds/<target>
#   fuzz/target/x86_64-unknown-linux-gnu/release/<target> \
#       -merge=1 -use_counters=0 fuzz/seeds/<target> fuzz/corpus/<target>
set -euo pipefail
cd "$(dirname "$0")/.."

SECS="${1:-120}"
shift || true

TARGETS=(parse responder initiator transport session_ops crypto_roundtrip)
for t in "${TARGETS[@]}"; do
    echo "==== fuzzing $t for ${SECS}s ===="
    mkdir -p "fuzz/corpus/$t" "fuzz/seeds/$t"
    cargo +"${NIGHTLY:-nightly}" fuzz run "$t" "fuzz/corpus/$t" "fuzz/seeds/$t" -- -max_total_time="$SECS" "$@"
done
echo "All targets completed with no crashes."
