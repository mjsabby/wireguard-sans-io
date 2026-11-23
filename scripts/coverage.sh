#!/usr/bin/env bash
# Source-based code coverage via -C instrument-coverage and the
# rustup llvm-tools component (no extra cargo plugins needed).
#
#   scripts/coverage.sh           # summary table, and the threshold
#   scripts/coverage.sh show      # annotated per-line report for src/
#
# The summary fails if the line coverage of the library falls below
# MIN_LINE_COVERAGE percent (default 94). "Of the library" means of the
# lines outside the `#[cfg(test)]` modules at the ends of the source
# files: those modules are test code, every line of which runs by
# construction, and llvm-cov's own TOTAL row counts them in — which makes
# the library look better covered than it is (96.0 % against 94.9 % at
# the time of writing). Both numbers are printed; the floor is on the
# library's.
#
# The number is a floor under what the tests already reach, so that code
# added without tests shows up — not a target, and no substitute for the
# tests saying something: that is what the mutation checks and the
# planted defects in the other scripts are for.
set -euo pipefail
cd "$(dirname "$0")/.."

MODE="${1:-report}"

# Locate llvm-profdata/llvm-cov from the rustup component.
SYSROOT=$(rustc --print sysroot)
TOOLS=$(find "$SYSROOT" -name llvm-profdata -path '*bin*' 2>/dev/null | head -1 | xargs dirname 2>/dev/null || true)
if [ -z "$TOOLS" ]; then
    echo "llvm-tools not found; installing the rustup component..."
    rustup component add llvm-tools
    TOOLS=$(find "$SYSROOT" -name llvm-profdata -path '*bin*' | head -1 | xargs dirname)
fi
PROFDATA="$TOOLS/llvm-profdata"
LLVMCOV="$TOOLS/llvm-cov"

COVDIR="target/coverage"
rm -rf "$COVDIR"
mkdir -p "$COVDIR"

echo "Running instrumented test suite..."
export RUSTFLAGS="-C instrument-coverage"
export LLVM_PROFILE_FILE="$PWD/$COVDIR/wg-%p-%m.profraw"
cargo test --tests --quiet >/dev/null

echo "Merging profiles..."
"$PROFDATA" merge -sparse "$COVDIR"/*.profraw -o "$COVDIR/wg.profdata"

# Collect the test executables that produced the profiles.
OBJECTS=$(cargo test --tests --no-run --message-format=json 2>/dev/null \
    | python3 -c '
import json, sys
for line in sys.stdin:
    try:
        m = json.loads(line)
    except json.JSONDecodeError:
        continue
    exe = m.get("executable")
    if exe and m.get("profile", {}).get("test"):
        print("-object", exe)
')

# shellcheck disable=SC2086
"$LLVMCOV" "$MODE" \
    --instr-profile="$COVDIR/wg.profdata" \
    --ignore-filename-regex='(registry|rustc/|\.rustup/|/tests/)' \
    $OBJECTS \
    ${MODE_FLAGS:-} | tee "$COVDIR/coverage.txt"

echo
echo "Report saved to $COVDIR/coverage.txt"

if [ "$MODE" = report ]; then
    MIN="${MIN_LINE_COVERAGE:-94}"
    # TOTAL row: regions, missed, cover, functions, missed, executed,
    # lines, missed, cover.
    ALL_LINES=$(awk '$1 == "TOTAL" { sub("%", "", $10); print $10 }' "$COVDIR/coverage.txt")
    if [ -z "$ALL_LINES" ]; then
        echo "FAIL: no TOTAL row in the coverage report."
        exit 1
    fi
    # The same per line, to leave the in-file test modules out.
    # shellcheck disable=SC2086
    "$LLVMCOV" export --format=lcov \
        --instr-profile="$COVDIR/wg.profdata" \
        --ignore-filename-regex='(registry|rustc/|\.rustup/|/tests/)' \
        $OBJECTS >"$COVDIR/coverage.lcov"
    LINE_COVERAGE=$(python3 -I - "$COVDIR/coverage.lcov" <<'EOF'
import re, sys
# (file, line) -> was it executed? A line can have several records (one
# per instance of a generic function): executed in any of them counts.
executed = {}
source = first_test_line = None
for record in open(sys.argv[1]):
    record = record.strip()
    if record.startswith("SF:"):
        # Where this file's test module begins: the `#[cfg(test)]` that
        # is followed by a module called `tests`.
        source, first_test_line = record[3:], None
        lines = open(source, encoding="utf-8").read().split("\n")
        for number, line in enumerate(lines, start=1):
            if line.strip() == "#[cfg(test)]" and number < len(lines) and re.match(
                r"\s*(pub(\(crate\))? )?mod tests\b", lines[number]
            ):
                first_test_line = number
                break
    elif record.startswith("DA:"):
        number, count = record[3:].split(",")[:2]
        if first_test_line is not None and int(number) >= first_test_line:
            continue
        key = (source, int(number))
        executed[key] = executed.get(key, False) or int(count) > 0
covered, total = sum(executed.values()), len(executed)
print(f"{100 * covered / total:.2f} {covered} {total}" if total else "")
EOF
    )
    if [ -z "$LINE_COVERAGE" ]; then
        echo "FAIL: no line records in the coverage export."
        exit 1
    fi
    read -r LIBRARY COVERED TOTAL <<<"$LINE_COVERAGE"
    {
        echo
        echo "Lines, with the in-file test modules counted in (the TOTAL row above): $ALL_LINES %"
        echo "Lines of the library alone:                                           $LIBRARY % ($COVERED of $TOTAL)"
    } | tee -a "$COVDIR/coverage.txt"
    if awk -v have="$LIBRARY" -v want="$MIN" 'BEGIN { exit !(have + 0 < want + 0) }'; then
        echo "FAIL: line coverage of the library, $LIBRARY %, is below the floor of $MIN %."
        exit 1
    fi
    echo "PASS: line coverage of the library $LIBRARY % (floor: $MIN %)."
fi
