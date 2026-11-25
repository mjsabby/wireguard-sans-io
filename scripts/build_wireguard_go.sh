#!/usr/bin/env bash
# Build wireguard-go — the reference userspace implementation, and the
# other end in scripts/interop_wireguard_go.sh — from source, at a pinned
# revision:
#
#   scripts/build_wireguard_go.sh       # → target/wireguard-go/wireguard-go
#
# Needs git, a Go toolchain, and the network the first time (for the
# source, and for the Go modules it depends on; go.sum in the pinned
# revision pins those). Go is looked for in $GO, then on PATH, then among
# the toolchains unpacked under ~/sdk (the newest of them).
#
# What the build writes is under target/: the source in
# target/wireguard-go-src/, Go's module and build caches in
# target/wireguard-go-cache/, the binary in target/wireguard-go/.
set -euo pipefail
# $GO can be a command on PATH or a path, and the path one relative to
# where the script was started: found before changing directory.
GO_BIN=""
if [ -n "${GO:-}" ]; then
    GO_BIN=$(command -v "$GO" || true)
    case "$GO_BIN" in
        /* | "") ;;
        *) GO_BIN="$PWD/$GO_BIN" ;;
    esac
fi
cd "$(dirname "$0")/.."

# The revision: a release tag and the commit it names. The commit is what
# is checked — a tag can be moved, a commit hash cannot.
TAG=0.0.20250522
COMMIT=f333402bd9cbe0f3eeb02507bd14e23d7d639280
# Upstream, then its mirror.
REPOSITORIES=(https://git.zx2c4.com/wireguard-go https://github.com/WireGuard/wireguard-go)

SRC=target/wireguard-go-src
CACHE=target/wireguard-go-cache
OUT=target/wireguard-go/wireguard-go

# ---- a Go toolchain ---------------------------------------------------------
if [ -n "${GO:-}" ]; then
    # $GO or nothing: no other toolchain is used behind the caller's back.
    missing="\$GO is '$GO', and that is not a go binary that runs."
elif command -v go >/dev/null 2>&1; then
    GO_BIN=$(command -v go)
    missing="'$GO_BIN' (the go on PATH) does not run."
else
    # Where the golang.org/dl commands (`goX.Y.Z download`) put toolchains,
    # and where one unpacked by hand goes (see below). The newest of them.
    GO_BIN=$(printf '%s\n' "$HOME"/sdk/go*/bin/go | sort -V | tail -n 1)
    missing="no Go toolchain: \$GO is not set, there is no go on PATH and none in ~/sdk/go*/bin/."
fi
if ! [ -x "$GO_BIN" ] || ! "$GO_BIN" version >/dev/null 2>&1; then
    case "$(uname -m)" in
        x86_64) arch=amd64 ;;
        aarch64 | arm64) arch=arm64 ;;
        *) arch='<arch>' ;;
    esac
    cat >&2 <<EOF
FAIL: $missing
Either point GO at a go binary:
    GO=/path/to/go scripts/build_wireguard_go.sh
or unpack a toolchain from https://go.dev/dl/ (the checksums are there too)
under ~/sdk, which needs no root; for instance:
    mkdir -p ~/sdk/go1.27.4
    curl -fsSL https://go.dev/dl/go1.27.4.linux-$arch.tar.gz |
        tar -xz --strip-components=1 -C ~/sdk/go1.27.4
EOF
    exit 1
fi
if ! command -v git >/dev/null 2>&1; then
    echo "FAIL: git is needed to fetch wireguard-go." >&2
    exit 1
fi

# ---- the source, at the pinned commit ---------------------------------------
# target/ is inside this repository's work tree. git must never take this
# repository for wireguard-go's — a missing or broken
# target/wireguard-go-src/.git would otherwise send the commands below up
# here — so its search for a repository stops at target/.
export GIT_CEILING_DIRECTORIES="$PWD/target"

# Up to date: the pinned commit is checked out and nothing was changed or
# added. (Go's caches are not in the source directory, so a build leaves
# it as it was.)
source_is_pinned() {
    [ -d "$SRC/.git" ] &&
        [ "$(git -C "$SRC" rev-parse --verify --quiet 'HEAD^{commit}' 2>/dev/null)" = "$COMMIT" ] &&
        [ -z "$(git -C "$SRC" status --porcelain)" ]
}
if ! source_is_pinned; then
    rm -rf "$SRC"
    mkdir -p "$SRC"
    git init --quiet "$SRC"
    fetched=""
    for repository in "${REPOSITORIES[@]}"; do
        echo "Fetching wireguard-go $TAG from $repository..."
        # Only the tagged commit; a server that cannot serve a shallow
        # history gets asked for the whole of it (a few megabytes).
        if git -C "$SRC" fetch --quiet --depth 1 "$repository" "refs/tags/$TAG" 2>/dev/null ||
            git -C "$SRC" fetch --quiet "$repository" "refs/tags/$TAG"; then
            fetched=$(git -C "$SRC" rev-parse --verify 'FETCH_HEAD^{commit}')
            break
        fi
    done
    if [ -z "$fetched" ]; then
        echo "FAIL: could not fetch wireguard-go $TAG from any of: ${REPOSITORIES[*]}" >&2
        exit 1
    fi
    if [ "$fetched" != "$COMMIT" ]; then
        echo "FAIL: tag $TAG is commit $fetched there, not the pinned $COMMIT." >&2
        exit 1
    fi
    # Detached: there is no branch to be on. (The advice git prints about
    # that is switched off for this one command.)
    git -C "$SRC" -c advice.detachedHead=false checkout --quiet --detach "$COMMIT"
fi

# ---- the build ---------------------------------------------------------------
# Go's caches go under target/ too, unless the environment already says
# where they are: the build then leaves nothing in the home directory.
export GOMODCACHE="${GOMODCACHE:-$PWD/$CACHE/mod}" GOCACHE="${GOCACHE:-$PWD/$CACHE/build}"
# No C toolchain needed, and none used if there is one: wireguard-go is
# pure Go on Linux, and this way the binary is the same statically linked
# one on every machine.
export CGO_ENABLED=0
# Nor does a Go workspace file somewhere above target/ have a say.
export GOWORK=off
mkdir -p "$(dirname "$OUT")"
out="$PWD/$OUT"
echo "Building $OUT with $("$GO_BIN" version | cut -d' ' -f3-)..."
# -modcacherw: Go makes its module cache read-only, and `cargo clean` (or
#   `rm -r target`) could then not remove it.
# -buildvcs=true: the commit the binary was built from, and whether the
#   source was modified, are recorded in the binary — and checked below.
(cd "$SRC" && "$GO_BIN" build -modcacherw -buildvcs=true -o "$out" .)

# What was built is what was pinned: the binary says which commit it was
# built from, and that the work tree had no changes.
built=$("$GO_BIN" version -m "$OUT")
if ! grep -q "vcs.revision=$COMMIT\$" <<<"$built" || ! grep -q 'vcs.modified=false$' <<<"$built"; then
    echo "$built" >&2
    echo "FAIL: $OUT was not built from an unmodified $COMMIT." >&2
    exit 1
fi
echo "Built $OUT: $("$OUT" --version | sed -n 1p), commit $COMMIT."
