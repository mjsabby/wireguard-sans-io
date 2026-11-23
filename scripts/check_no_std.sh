#!/usr/bin/env bash
# Does the core really need neither `std` nor an allocator?
#
# Compiling the library for a `no_std` target does not show it: such
# targets still ship the `alloc` crate (and some ship `std`), and a library
# may use either without anyone noticing until a final image is linked.
#
# So this links one: `probes/freestanding`, which goes through every public
# entry point of the core, for a target that has no `std`, and without
# providing a global allocator. It links only if nothing in it needs
# either.
#
# The check first proves it can fail: the same image with a planted heap
# allocation, and with a planted use of `std`, must not build.
set -euo pipefail
cd "$(dirname "$0")/../probes/freestanding"

TARGET=x86_64-unknown-none

if ! rustup target list --installed 2>/dev/null | grep -qx "$TARGET"; then
    echo "FAIL: target $TARGET is not installed (rustup target add $TARGET)"
    exit 1
fi

# $1: feature that plants the problem; $2: what the compiler must say.
must_not_build() {
    local log
    if log=$(cargo build --quiet --release --target "$TARGET" --features "$1" 2>&1); then
        echo "FAIL: an image with $1 built; this check cannot be trusted."
        exit 1
    fi
    if ! grep -q "$2" <<<"$log"; then
        echo "FAIL: the image with $1 failed to build, but not for the expected reason:"
        sed 's/^/    /' <<<"$log" | head -20
        exit 1
    fi
    echo "    ...$1 is refused, as it must be."
}

echo "Self-test: images with a planted allocation and a planted use of std..."
must_not_build canary-alloc "no global memory allocator found"
must_not_build canary-std "can't find crate for \`std\`"

echo "Building the image for $TARGET (no std, no allocator)..."
cargo build --quiet --release --target "$TARGET"
echo "PASS: every public entry point links without std and without an allocator."
