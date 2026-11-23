#!/usr/bin/env bash
# Is there any panic machinery left in the optimised core?
#
# `probes/freestanding` is an image with the whole public API of the core
# in it: the address of every public function, method and
# trait-implementation method is taken (so each exists as a function of
# its own, compiled for any arguments), for three crypto providers; the
# API is also called the way a caller calls it, with buffers whose
# *lengths* the optimiser cannot know; and everything the library can
# print is printed. The image is linked as machine code — not an archive
# of compiler bitcode — and searched for anything belonging to Rust's
# panic machinery. A panic branch the optimiser could not prove dead keeps
# `core::panicking` in the image; if every such branch is gone, so is the
# machinery.
#
# Three things are checked before the answer is believed:
#
#   1. That the image covers the API. The list of what it takes the
#      address of is generated from rustdoc's description of the crate
#      (`scripts/probe_api.py`), and compared here with the one that is
#      checked in. (This step needs a nightly toolchain — rustdoc's JSON
#      output is unstable: the one called `nightly`, or the one named in
#      NIGHTLY. Without one it is skipped, and says so; with
#      REQUIRE_NIGHTLY=1 — which CI sets — that is a failure.
#      UPDATE=1 writes the list instead of comparing it.)
#   2. That the check can fail: an image with an unchecked index planted
#      in the probe must be flagged — and so must images built from a copy
#      of the *library* with a panic planted in it, of the three shapes
#      that got past an earlier version of this check: one that depends on
#      the length of a caller's buffer, one in a function nothing calls,
#      one in generic code.
#   3. That the image can be read at all.
#
# What this covers: the core — default provider, a keystream backend of
# the embedder's, a foreign provider — in the build configurations listed
# below (every optimisation level from 1 up, for speed and for size, with
# and without link-time optimisation), on the target below, with the
# toolchain it is run with. It complements the clippy wall (which forbids
# the source constructs that panic).
#
# What it does not cover, and what is there (looked at with this probe,
# not checked here):
#   * opt-level 0. The library's code has no panic machinery there
#     either; libcore's formatting code has (`char::encode_utf8_raw`),
#     which is reached by printing.
#   * builds with debug assertions and overflow checks. Fully optimised
#     (opt-level 3, fat LTO) there is none; less optimised, libcore's
#     iterators keep their overflow checks.
#   * the `embed` and `simd` crates.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO=$PWD
PROBE=probes/freestanding
TARGET=x86_64-unknown-none
PANIC_SYMBOLS='panicking|panic_|rust_begin_unwind|unwrap_failed|expect_failed|slice_index|bounds_check|division_by_zero|len_mismatch'

# The configurations the claim is made for: "opt-level lto codegen-units
# cargo-arguments". The first is the probe's own profile.
CONFIGS=(
    "3 fat 1"
    "3 fat 1 --no-default-features"
    "2 fat 1"
    "s fat 1"
    "z fat 1"
    "3 thin 1"
    "s thin 1"
    "3 false 16"
    "z false 16"
    "1 false 16"
)
# QUICK=1: the first configuration only (the self-tests are not shortened).
if [ "${QUICK:-0}" = 1 ]; then
    CONFIGS=("${CONFIGS[0]}")
fi

if ! rustup target list --installed 2>/dev/null | grep -qx "$TARGET"; then
    echo "FAIL: target $TARGET is not installed (rustup target add $TARGET)"
    exit 1
fi

SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT

# Build the probe in directory $1 with profile "$2 $3 $4" and the cargo
# arguments that follow; print the path of the image.
build() {
    local dir=$1 opt=$2 lto=$3 units=$4
    shift 4
    local target_dir="$REPO/$PROBE/target/check-$opt-$lto-$units"
    (
        cd "$dir"
        CARGO_PROFILE_RELEASE_OPT_LEVEL=$opt \
            CARGO_PROFILE_RELEASE_LTO=$lto \
            CARGO_PROFILE_RELEASE_CODEGEN_UNITS=$units \
            CARGO_TARGET_DIR=$target_dir \
            cargo build --quiet --release --target "$TARGET" "$@"
    ) >&2
    echo "$target_dir/$TARGET/release/wireguard-freestanding"
}

# The panic machinery in image $1, one symbol per line; nothing if there
# is none. Refuses to conclude anything from an image it cannot read: the
# entry point and the core's own code must be listed.
panic_symbols() {
    local listing
    listing=$(nm -C "$1")
    if ! grep -q ' _start$' <<<"$listing" || ! grep -q 'wireguard_sans_io::' <<<"$listing"; then
        echo "FAIL: cannot read the symbols of $1 (stripped, or not machine code?)" >&2
        return 1
    fi
    grep -E "$PANIC_SYMBOLS" <<<"$listing" || true
}

# Who calls it, in image $1.
callers() {
    objdump -d -C --no-show-raw-insn "$1" |
        awk '/^[0-9a-f]+ <.*>:$/ { fn = $0 }
             /call|jmp/ && /panic|unwrap_failed|expect_failed|slice_index|bounds_check|len_mismatch/ { print "    " fn }' |
        sort | uniq -c | sort -rn | head -20
}

# ---- 1. does the probe cover the public API? ---------------------------------
echo "Coverage: is every public function in the image?"
doc_dir="$REPO/$PROBE/target/api-doc"
if CARGO_TARGET_DIR=$doc_dir cargo +"${NIGHTLY:-nightly}" rustdoc --quiet --lib -- \
    -Z unstable-options --output-format json >"$SCRATCH/rustdoc.log" 2>&1; then
    # (The generator refuses what it has no rule for — a new kind of
    # generic argument, say — and says which: that has to be seen.)
    if ! python3 -I scripts/probe_api.py list "$doc_dir/doc/wireguard_sans_io.json" >"$SCRATCH/api.txt" 2>"$SCRATCH/count" ||
        ! python3 -I scripts/probe_api.py keep "$SCRATCH/api.txt" >"$SCRATCH/keep.rs" 2>"$SCRATCH/count"; then
        echo "FAIL: scripts/probe_api.py could not list the API:"
        sed 's/^/    /' "$SCRATCH/count"
        exit 1
    fi
    if [ "${UPDATE:-0}" = 1 ]; then
        cp "$SCRATCH/api.txt" "$PROBE/api.txt"
        cp "$SCRATCH/keep.rs" "$PROBE/src/keep.rs"
        echo "    ...$PROBE/api.txt and src/keep.rs written ($(sed 's/.*: //' "$SCRATCH/count"))."
    elif ! cmp -s "$SCRATCH/api.txt" "$PROBE/api.txt" || ! cmp -s "$SCRATCH/keep.rs" "$PROBE/src/keep.rs"; then
        echo "FAIL: the public API has changed and the probe's list of it has not:"
        diff "$PROBE/api.txt" "$SCRATCH/api.txt" | sed 's/^/    /' | head -20
        echo "Run: UPDATE=1 scripts/check_no_panic.sh"
        exit 1
    else
        echo "    ...yes: $(sed 's/.*: //' "$SCRATCH/count") taken, as rustdoc lists them."
    fi
elif [ "${REQUIRE_NIGHTLY:-0}" = 1 ]; then
    echo "FAIL: REQUIRE_NIGHTLY=1 and rustdoc's JSON output could not be had:"
    sed 's/^/    /' "$SCRATCH/rustdoc.log" | tail -5
    exit 1
else
    echo "    ...NOT CHECKED: that needs a nightly toolchain (rustdoc's JSON output)."
    echo "       The image has what $PROBE/api.txt lists; whether that is still"
    echo "       everything is not known here."
fi

# ---- 2. can the check fail? ---------------------------------------------------
echo "Self-test: an image with an unchecked index planted in the probe..."
image=$(build "$PROBE" ${CONFIGS[0]} --features canary-panic)
if [ -z "$(panic_symbols "$image")" ]; then
    echo "FAIL: the planted panic was not detected; this check cannot be trusted."
    exit 1
fi
echo "    ...is flagged, as it must be."

# A copy of the library with one line added after the line that matches
# $2 in file $1: the probe must find it.
plant() {
    local file=$1 after=$2 line=$3 what=$4
    local copy="$SCRATCH/plant"
    rm -rf "$copy"
    mkdir -p "$copy/$PROBE"
    cp -r Cargo.toml src "$copy/"
    cp -r "$PROBE/Cargo.toml" "$PROBE/Cargo.lock" "$PROBE/src" "$copy/$PROBE/"
    python3 -I - "$copy/$file" "$after" "$line" <<'EOF'
import sys
path, after, line = sys.argv[1:]
text = open(path).read()
if text.count(after) != 1:
    sys.exit(f"the place to plant a panic ({after!r}) is found {text.count(after)} times in {path}")
open(path, "w").write(text.replace(after, after + "\n" + line))
EOF
    echo "Self-test: the library with a panic planted $what..."
    image=$(build "$copy/$PROBE" ${CONFIGS[0]})
    if [ -z "$(panic_symbols "$image")" ]; then
        echo "FAIL: the planted panic was not detected; this check cannot be trusted."
        exit 1
    fi
    echo "    ...is flagged, as it must be."
}
plant src/tunnel.rs '    ) -> Result<PollOutput<'"'"'a>, Error> {' \
    '        let _ = out.split_at_mut(32);' \
    "in \`Tunnel::poll\`, for a caller's buffer shorter than 32 bytes"
plant src/crypto/aead.rs '    open_with::<Scalar>(key, nonce, aad, ciphertext_and_tag, out)' \
    '        .map(|n| out.split_at_mut(ciphertext_and_tag.len()).0.len().min(n))' \
    'in `aead::open`, which nothing in the library calls'
plant src/crypto/kdf.rs '    key: &[u8; 32],
    input: &[u8],
    outputs: [&mut [u8; 32]; N],
) {' \
    '    let _ = outputs.split_at(1);' \
    'in the generic `kdf_into`, for an instance the protocol does not use'

# ---- 3. the image --------------------------------------------------------------
failed=0
for config in "${CONFIGS[@]}"; do
    # shellcheck disable=SC2086
    set -- $config
    echo "Image: opt-level $1, lto $2, codegen-units $3${4:+, $4}..."
    # shellcheck disable=SC2086
    image=$(build "$PROBE" $config)
    found=$(panic_symbols "$image")
    if [ -n "$found" ]; then
        echo "FAIL: panic machinery in the image:"
        sed 's/^/    /' <<<"$found"
        echo "Called from:"
        callers "$image"
        failed=1
    else
        echo "    ...none ($(size "$image" | awk 'NR == 2 { print $1 }') bytes of code)."
    fi
done
if [ "$failed" = 1 ]; then
    exit 1
fi
echo "PASS: no panic machinery in the optimised image: every public function, three providers, ${#CONFIGS[@]} build configurations."
