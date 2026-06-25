# wireguard-bench

Comparative benchmarks for **`wireguard-embed`** (the std/alloc driver
around the `wireguard-sans-io` no_std core) against
**BoringTun** and — via the UDP-loopback harness — **wireguard-go** and
the Linux kernel module.

## In-process: `wireguard-embed` vs BoringTun

> This crate is **excluded from the parent workspace** because it needs
> a sibling `../../boringtun` checkout (which CI doesn't have). Run
> everything from this directory.

```sh
git clone https://github.com/cloudflare/boringtun ../../boringtun  # once
cd bench
cargo bench
```

Both implementations are driven through identical handshake + transport
flows on identical key material (`bench/src/lib.rs::Fixture`), so the
only difference measured is the protocol/crypto implementation itself.

### Results (x86_64, single core, this machine)

| Benchmark | `wireguard-embed` | BoringTun | ratio |
|---|---:|---:|---:|
| **handshake** (full 1-RTT, both sides) | **566 µs** | 619 µs | **0.91× ✓** |
| transport_roundtrip / 64 B | 911 ns | 448 ns | 2.04× |
| transport_roundtrip / 576 B | 3.45 µs | 903 ns | 3.82× |
| transport_roundtrip / 1420 B | 7.76 µs | 1.76 µs | 4.41× |
| encapsulate_only / 64 B | 419 ns | 195 ns | 2.15× |
| encapsulate_only / 1420 B | 3.81 µs (355 MB/s) | 882 ns (1.50 GB/s) | 4.32× |
| decapsulate_only / 64 B | 647 ns | 431 ns | 1.50× |
| decapsulate_only / 1420 B | 4.36 µs (310 MB/s) | 1.27 µs (1.04 GB/s) | 3.43× |

**Reading the numbers:**

* **Handshake — we're 8 % faster.** Both stacks use pure-Rust X25519
  (ours in-tree, BoringTun via `x25519-dalek`); the gap comes from the
  D-1 fix (one fewer DH on the responder path) and from BoringTun's
  per-handshake-AEAD heap allocation
  (`aead_chacha20_open` does `data.to_owned()`).
* **Transport — BoringTun is 2–4.4× faster, scaling with packet size.**
  This is exactly the cost of `#![forbid(unsafe_code)]` + zero
  dependencies: BoringTun's data path is `ring`'s hand-tuned
  AVX2/AVX-512 **assembly** ChaCha20-Poly1305; ours is portable scalar
  safe Rust. At 1420 B that's ≈ 2.8 Gbit/s vs ≈ 12 Gbit/s
  encapsulate-only on this CPU.
* The wrapper overhead (two clock reads + rate-limiter peek per call)
  is ~40–60 ns; negligible at MTU, visible at 64 B. Future buffer-pool
  work removes the `to_vec()` in `roundtrip` (currently a benchmark
  artefact, not production cost).

If you need ring-class transport throughput **and** the no_std core,
the seam is `wireguard_sans_io::crypto::aead` — a SIMD `seal`/`open`
behind a feature flag would close the gap without touching protocol
logic.

## Out-of-process: vs wireguard-go / kernel

`wireguard-go` is a Go binary and can't be linked in-process from Rust,
so the fair comparison is UDP-loopback throughput with identical syscall
overhead on every contestant:

```sh
cargo build -p wireguard-bench --release --bin udp_throughput
```

* **`echo` mode** stands up a `wireguard-embed` responder on a UDP port
  that decrypts every transport packet and re-encrypts it back.
* **`pump` mode** is the initiator: handshakes with any WireGuard
  endpoint, floods 1420-byte packets for N seconds, and reports MB/s +
  pps from decrypted echoes.

```sh
# wireguard-embed vs itself (baseline):
A_PRIV=$(wg genkey); A_PUB=$(echo "$A_PRIV" | wg pubkey)
B_PRIV=$(wg genkey); B_PUB=$(echo "$B_PRIV" | wg pubkey)
target/release/udp_throughput echo 51900 "$B_PRIV" "$A_PUB" &
target/release/udp_throughput pump 127.0.0.1:51900 "$A_PRIV" "$B_PUB" 10

# vs wireguard-go: bring up a wireguard-go interface, attach a
# tun-side echo (e.g. `socat TUN:10.9.0.1/24,iff-up EXEC:cat`), then
# pump at its listen-port. Same for the kernel module / boringtun-cli.
```

Because `pump` is the same binary in every run, the comparison isolates
the *peer's* encrypt/decrypt cost plus its socket → tun → socket path.

## What's where

| File | Purpose |
|---|---|
| `../embed/` | the **production** std driver — usable as a library (BoringTun-style `Tunn` API, built-in clock/RNG/rate-limiter/queue, `BufferPool` hook reserved) |
| `src/lib.rs` | benchmark scaffolding: matched `EmbedPair` / `BoringPair` fixtures |
| `benches/compare.rs` | the Criterion in-process suite |
| `src/udp_throughput.rs` | the out-of-process harness for wireguard-go / kernel |
