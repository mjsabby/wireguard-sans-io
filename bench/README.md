# wireguard-bench

Comparative benchmarks for **`wireguard-embed`** (the std/alloc driver
around the `wireguard-sans-io` no_std core) against
**BoringTun** and — via the UDP-loopback harness — **wireguard-go** and
the Linux kernel module.

## In-process: `wireguard-embed` vs BoringTun

> This crate is **excluded from the parent workspace** because it needs
> a BoringTun checkout next to this repository, which a plain checkout of
> this repository does not come with. Run everything from this directory.
> (CI clones BoringTun for one job, which builds this crate and runs every
> benchmark once — so that an API change cannot break it unnoticed; it
> measures nothing.)

```sh
# from the repository's root; the clone only once
git clone https://github.com/cloudflare/boringtun ../boringtun
cd bench
cargo bench
```

(Without the checkout, point the `boringtun` dependency in `Cargo.toml` at
the repository instead:
`boringtun = { git = "https://github.com/cloudflare/boringtun", default-features = false }`.)

Both implementations are driven through identical handshake + transport
flows on identical key material (`bench/src/lib.rs::Fixture`), so the
only difference measured is the protocol/crypto implementation itself.

### Results (x86_64 — a Zen 5 — one core, median of three runs; BoringTun 0.7.1 @ `6dcc889a`)

| Benchmark | `wireguard-embed` | BoringTun | ratio |
|---|---:|---:|---:|
| **handshake** (both ends made, full 1-RTT, first packet) | 226 µs | 280 µs | 0.81× |
| transport_roundtrip / 64 B | 336 ns | 337 ns | 1.00× |
| transport_roundtrip / 576 B | 547 ns | 594 ns | 0.92× |
| transport_roundtrip / 1280 B | 908 ns | 1.11 µs | 0.82× |
| transport_roundtrip / 1420 B | 974 ns | 1.17 µs | 0.83× |
| encapsulate_only / 64 B | 156 ns | 153 ns | 1.02× |
| encapsulate_only / 1420 B | 458 ns (2.89 GiB/s) | 545 ns (2.43 GiB/s) | 0.84× |
| decapsulate_only / 64 B | 171 ns | 181 ns | 0.95× |
| decapsulate_only / 1420 B | 482 ns (2.74 GiB/s) | 598 ns (2.21 GiB/s) | 0.81× |

### The same on a CPU without AVX-512 (a Zen 3 with AVX2 — one core, one run; the same BoringTun)

| Benchmark | `wireguard-embed` | BoringTun | ratio |
|---|---:|---:|---:|
| **handshake** (both ends made, full 1-RTT, first packet) | 352 µs | 412 µs | 0.85× |
| transport_roundtrip / 64 B | 327 ns | 310 ns | 1.05× |
| transport_roundtrip / 576 B | 828 ns | 620 ns | 1.34× |
| transport_roundtrip / 1280 B | 1.47 µs | 1.15 µs | 1.28× |
| transport_roundtrip / 1420 B | 1.62 µs | 1.24 µs | 1.30× |
| encapsulate_only / 64 B | 169 ns | 137 ns | 1.24× |
| encapsulate_only / 1420 B | 794 ns (1.67 GiB/s) | 609 ns (2.17 GiB/s) | 1.30× |
| decapsulate_only / 64 B | 165 ns | 165 ns | 1.00× |
| decapsulate_only / 1420 B | 801 ns (1.65 GiB/s) | 595 ns (2.22 GiB/s) | 1.35× |

Here the handshake is ours by a sixth, small packets are level, and
packets of a few hundred bytes and more are BoringTun's by a third. The
last is the keystream's width and the Poly1305 — eight blocks at a time
and safe Rust here, `ring`'s assembly for both there.

Small packets were not level until the keystream had a kernel for them.
A 64-byte packet is two blocks of keystream, and they used to be the
scalar code's whatever the CPU: 700 of the 920 cycles it took to
encapsulate such a packet on this machine, and three fifths more time
than BoringTun's assembly, which does both blocks in one pass
(roundtrip 482 ns against 301). Now they are a pair of blocks in 256-bit
registers (`simd/src/avx2.rs`: 300 cycles for the two), and packets of
up to 320 bytes two or three such pairs at once. Of what is left of the
difference when a 64-byte packet is encapsulated, half is the driver
reading the clock for every packet (16 ns), which BoringTun does not.

**Reading the numbers:**

* **Which keystream this is.** `wireguard-embed` uses the widest ChaCha20
  keystream the CPU has, found when the program runs. On this machine
  that is AVX-512 — two interleaved sixteen-block states, the AEAD's
  one-time key coming out of the same pass — and the table above is
  about that. BoringTun's data path is `ring`'s assembly
  ChaCha20-Poly1305. The AEAD by itself at 1420 bytes, in cycles on this
  machine: 2,350 with the AVX-512 keystream, 3,400 with the AVX2 one,
  7,900 with the core's scalar code — and 2,810 for `ring`. So on an
  x86_64 CPU without AVX-512 BoringTun is ahead at MTU size, not
  behind: by a third on the one such CPU this was measured on (the
  second table). The 64-byte rows do not depend on the keystream's
  width. (The Poly1305 in every case is the core's safe Rust.) Nothing
  here was measured on aarch64 or on an Intel CPU — and the first table
  is from before small packets had a kernel of their own: on that
  machine, whose vector unit takes two cycles over each step where the
  second machine's takes one, the kernel is expected to be worth
  little, and has not been measured.
* **What "handshake" is.** Every iteration makes both ends from fixed
  keys — each derives its public key and the static-static secret — and
  then runs the handshake to the first packet: twelve scalar
  multiplications, four of them construction. Ours are in-tree (the
  public keys by a ladder made for the base point), BoringTun's
  `x25519-dalek`'s.
* **The build.** The repository's: AVX2 enabled for the whole program
  (`.cargo/config.toml`), thin LTO and one codegen unit, as in the
  workspace. A build without the CPU flag — what a crate that depends on
  these crates gets — is within 2 % of these for packets.
* **`transport_roundtrip/wireguard-embed-in-place`** (not in the table: it
  has no BoringTun counterpart) decrypts in the buffer the datagram was
  written to — the receive path the async driver uses — instead of copying
  it first: 934 ns at 1420 B against 974 ns. The like-for-like
  `roundtrip` lines of both implementations include one `to_vec()` of the
  datagram.
* **All of these are steady-state numbers**: packet after packet on an
  established session. (`decapsulate_only` used to measure the first
  packet on a freshly made pair — the one that confirms the session —
  for both implementations; it now measures what its name says.)
* **Small packets have a kernel of their own.** A packet of up to 64
  bytes is two blocks of keystream in all — the one the authenticator
  key comes from, and one more — and a stride of eight, sixteen or
  thirty-two is no way to make two. On x86_64 with AVX2 they are a pair
  of blocks side by side in 256-bit registers (`simd/src/avx2.rs`), which
  costs less than one block of the scalar code that used to make both;
  up to six blocks, and tails of that size behind whole strides, are two
  or three such pairs at once. (NEON still hands one or two blocks to
  the scalar code.)
* Times move by a tenth with this machine's clock from one hour to the
  next; the ratios are steadier than the columns.

If you need `ring`-class transport throughput **and** the no_std core, the
seam is `wireguard_sans_io::CryptoProvider`: a provider with a faster AEAD
changes nothing in the protocol logic.

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
  endpoint, sends 1420-byte packets for N seconds — as fast as their
  echoes come back, with 64 in flight (or as many as a fifth argument
  says) — and reports MB/s and packets per second from the decrypted
  echoes, and how many packets were not echoed. A lost packet is noticed
  when the echo of a later one arrives, so loss on the path slows the
  pump down in proportion and does not stall it. Its packets have a
  valid IPv4 header, so that a kernel will forward them.

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

`scripts/perf_vs_kernel.sh` does this for three peers in a network
namespace of its own, without root: `echo` mode, the kernel's WireGuard
and wireguard-go (built by `scripts/build_wireguard_go.sh`). For the two
that are interfaces the echo is the kernel's IP forwarding: the
interface's route for the pump's addresses is the interface itself, so
what it decrypts goes straight back to the peer it came from. With
`PERF=1` the script counts the cycles of all cores during each run.

On the Zen 3 above (sixteen cores, Linux 7.3; 32 packets in flight, the
pump pinned to one core), one run of twelve seconds each:

| the pump's peer | packets echoed a second | cycles per packet, all cores | of them in user space | in the kernel |
|---|---:|---:|---:|---:|
| `wireguard-embed`, `echo` mode (one thread; no TUN device, no IP stack) | 326,000 | 28,500 | 16,100 | 12,500 |
| the kernel's WireGuard, forwarding | 212,000 | 85,700 | 8,300 | 77,500 |
| wireguard-go 0.0.20250522, forwarding through its TUN device | 234,000 | 93,700 | 52,600 | 41,100 |

What these say, and what they do not:

* Every row has the pump in it — about 14,000 cycles a packet, half of
  the first row: it encrypts, decrypts and makes two system calls per
  packet, as `echo` mode does.
* This is **one flow with a small window**, on loopback. The kernel
  hands each packet to another core twice, to decrypt and to encrypt;
  with 32 packets in flight on a machine of 32 hardware threads those
  cores are asleep when a packet comes. A profile of the kernel's run
  has 8 % of all cycles in its ChaCha20 and Poly1305 and most of the
  rest in waking up, idling and locking. What the kernel is built for —
  many flows, every core busy — is not what this measures, and the
  kernel's row is not its capacity.
* `echo` mode is the driver and a socket. The other two also route the
  packet through the kernel's IP stack, and wireguard-go through a TUN
  device as well (two more system calls a packet).
* The window is 32 and not the pump's own 64 because a datagram the
  kernel has forwarded is charged to the pump's socket buffer at about
  twice its length: with 64 in flight a sixth of the echoes did not fit
  a buffer of the default size, and the pump measured that.

Because `pump` is the same binary in every run, the comparison isolates
the *peer's* encrypt/decrypt cost plus its socket → tun → socket path —
for a peer that is slower than the pump. The pump is one thread that
makes one system call per packet each way; it levelled off at about
300,000 packets a second on the Zen 5 when that was looked at, and a
peer that can do more than the pump measures the pump.

## What's where

| File | Purpose |
|---|---|
| `../embed/` | the **production** std driver — usable as a library (BoringTun-style `Tunn` API, built-in clock/RNG/rate-limiter/queue/buffer pool, tokio event loop) |
| `src/lib.rs` | benchmark scaffolding: matched `EmbedPair` / `BoringPair` fixtures |
| `benches/compare.rs` | the Criterion in-process suite |
| `benches/chacha.rs` | the keystream backends side by side, and this library's AEAD next to `ring`'s |
| `src/udp_throughput.rs` | the out-of-process harness for wireguard-go / kernel |
| `../scripts/perf_vs_kernel.sh` | runs it against `echo` mode, the kernel and wireguard-go, with cycle counts |
