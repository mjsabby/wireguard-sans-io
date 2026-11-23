#!/usr/bin/env bash
# Where do secrets end up in memory?
#
# Runs three probes in `probes/`:
#
#   stack_residue    after every kind of public call — each primitive by
#                    itself (the curve arithmetic, the hashes and the key
#                    derivation, the cipher with every keystream backend
#                    this machine has, the AEADs), key generation and the
#                    constructors, then a tunnel's whole life with the
#                    default provider and with the SIMD keystream: is
#                    any secret the call handled still readable in dead
#                    stack memory? As the byte string it is — whole, or
#                    eight bytes of it in a row, what is left of a copy
#                    that something has since written over the rest of —
#                    or in a form the arithmetic had it in (field-element
#                    limbs, the words of a cipher key or state, of a
#                    hash's working vector, of an authenticator key)? A
#                    single 64-bit word of such a value counts as found,
#                    and two 32-bit ones.
#   memory_residue   at every stage of a tunnel's life: does it hold
#                    exactly the secrets it needs — and nothing at all,
#                    nor a device, once dropped, whatever state it was
#                    dropped in?
#   driver_residue   the std driver (`wireguard-embed`): what do creating
#                    and dropping a `Tunn` leave of its keys on the stack?
#
# each in three builds, because what a compiler leaves on the stack depends
# on how it optimises: unoptimised (opt-level 0 — what a plain `cargo
# build` of a dependent crate uses), this repository's dev profile
# (opt-level 1) and its release profile (opt-level 3, thin LTO). On
# x86-64 the release build is run a second time for the baseline CPU —
# without the `-C target-cpu` that this repository's `.cargo/config.toml`
# adds, which is how a crate that depends on the library is built unless
# it says otherwise (and there the compiler has fewer registers and no
# wide moves to keep things out of memory with).
#
# Three things are not held against a build short of full optimisation;
# the probes list what they find of them and do not count it:
#
#   * unoptimised: the word forms, and pieces of a byte string (there, a
#     word loaded from it). Without an optimiser every expression of the
#     arithmetic has a stack slot of its own, in frames deeper than the
#     library overwrites afterwards. Secrets as whole byte strings are
#     counted in every build.
#   * unoptimised: the SIMD keystream backends called by themselves.
#     (Their kernels are vector intrinsics, each a function call there,
#     in frames tens of kilobytes deep. A tunnel's life with the SIMD
#     keystream is still looked at.)
#   * unoptimised and dev: the functions that *return* a possibly secret
#     result by value (`blake2s::hash`, `kdf::kdf3`, …). There the result
#     is in the function's own dead frame as well as wherever the caller
#     received it; each has a form that writes in place, which is
#     checked everywhere.
#
# The probes first prove that they can see what they are looking for (a
# secret left behind on purpose — whole, as scattered words, and with its
# beginning written over; a live session's keys, a stored cookie, a
# device's secrets) and fail with status 2 if they cannot — and that the
# library's stack scrub leaves no byte of the range it is given as it
# was.
#
# If this machine can run aarch64 programs under emulation (the
# `aarch64-unknown-linux-musl` target and `qemu-aarch64`), the stack
# probe's release build is run there as well — the NEON keystream.
# Without them that step says so and is skipped; REQUIRE_AARCH64=1 makes
# their absence a failure.
#
# This is evidence about the targets and the compiler it runs with, not
# a proof about others. See EMBEDDER_OBLIGATIONS.md §10.
set -euo pipefail
cd "$(dirname "$0")/../probes"

status=0
# name | cargo profile | extra environment
for build in "unoptimised|dev|CARGO_PROFILE_DEV_OPT_LEVEL=0 CARGO_TARGET_DIR=target/opt0 WG_PROBE_UNOPTIMISED=1" \
             "dev|dev|" \
             "release|release|"; do
    IFS='|' read -r name profile extra <<<"$build"
    for probe in stack_residue memory_residue driver_residue; do
        echo "==== $probe ($name build)"
        # shellcheck disable=SC2086  # `extra` is a list of VAR=value words
        if ! env $extra cargo run --quiet --profile "$profile" --bin "$probe"; then
            status=1
        fi
    done
done

# The release build as a dependent crate gets it by default.
if [ "$(uname -m)" = x86_64 ]; then
    for probe in stack_residue memory_residue driver_residue; do
        echo "==== $probe (release build, baseline x86-64)"
        if ! RUSTFLAGS="-C target-cpu=x86-64" CARGO_TARGET_DIR=target/baseline \
            cargo run --quiet --release --bin "$probe"; then
            status=1
        fi
    done
fi

# The stack probe on aarch64, under emulation.
cross=aarch64-unknown-linux-musl
if rustup target list --installed 2>/dev/null | grep -qx "$cross" && command -v qemu-aarch64 >/dev/null; then
    echo "==== stack_residue (release build, aarch64 under qemu)"
    if ! CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER:-rust-lld}" \
        CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER=qemu-aarch64 \
        cargo run --quiet --release --target "$cross" --bin stack_residue; then
        status=1
    fi
elif [ "${REQUIRE_AARCH64:-0}" = 1 ]; then
    echo "FAIL: REQUIRE_AARCH64=1, and the target $cross or qemu-aarch64 is not here."
    status=1
else
    echo "==== stack_residue on aarch64: NOT RUN (needs the target $cross and qemu-aarch64)"
fi

if [ "$status" -eq 0 ]; then
    echo "PASS: no secret residue found."
else
    echo "FAIL: see above."
fi
exit "$status"
