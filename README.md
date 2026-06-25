# wireguard-sans-io

A **sans-I/O**, **`#![no_std]`**, **zero-allocation**, **zero-dependency**,
**panic-free** implementation of the WireGuard® protocol in Rust 2024.

The library implements the complete protocol — the Noise IKpsk2 handshake,
cookie-based DoS mitigation, transport encryption with replay protection,
and the whitepaper §6 timer state machine — without ever touching a socket,
reading a clock, spawning a thread, or allocating a byte. Callers feed in
datagrams, buffers, the current time and entropy; the library hands back
datagrams to send and plaintext that was received.

```rust
use wireguard_sans_io::{Config, Encapsulated, Now, Received, StaticSecret, Tunnel};

let mut tunnel = Tunnel::new(Config::new(local_secret, peer_public))?;

// Send path: plaintext in, datagram out (or a handshake initiation if no
// session exists yet — the payload is then not consumed).
match tunnel.encapsulate(now, packet, &mut buf, &mut rng)? {
    Encapsulated::Transport(wire) => socket.send(wire)?,
    Encapsulated::HandshakeInitiation(wire) => socket.send(wire)?, // retry later
}

// Receive path: datagram in; plaintext, a reply, or a state change out.
match tunnel.decapsulate(now, remote_addr, under_load, datagram, &mut buf, &mut rng)? {
    Received::Data(plain) => deliver(plain),
    Received::Reply(wire) => socket.send(wire)?, // handshake response / cookie
    Received::Keepalive | Received::HandshakeComplete | Received::CookieStored => {}
}

// Timers: poll whenever `tunnel.next_wake()` falls due.
while let PollOutput::Send(wire, _why) = tunnel.poll(now, &mut buf, &mut rng)? {
    socket.send(wire)?;
}
```

A complete runnable two-peer example lives in the `Tunnel` rustdoc (and is
exercised as a doctest).

## Design rules

| Rule | Enforcement |
|---|---|
| No I/O, no clocks, no global state | API shape: time (`Now`) and entropy (`EntropySource`) are arguments; outputs go to caller buffers |
| `#![no_std]`, no `alloc` | The crate cannot allocate — verified by building for a core-only target (`x86_64-unknown-uefi`) |
| No `unsafe` | `#![forbid(unsafe_code)]` + **zero dependencies**, so the guarantee covers every line involved, including all cryptography |
| No panics | Clippy deny-wall (`indexing_slicing`, `arithmetic_side_effects`, `unwrap_used`, …) **and** `scripts/check_no_panic.sh`, which scans the optimized rlib for `core::panicking` references — there are none |
| Defensive | mac1 verified before any expensive work; verify-then-decrypt AEAD (forgeries never touch output buffers); replay window advanced only post-authentication; constant-time comparisons; secrets wiped on drop; monotonicity clamp on hostile clocks; internal invariant failures surface as `Error::Internal`, never as panics |

## Embedding guide: what the library deliberately leaves to you

This crate is the **protocol state machine only**. Everything that needs
a socket, a clock, an allocator, or a per-IP table lives in your code.
This section spells out each obligation, with the equivalent from
Cloudflare's BoringTun (which bundles these in) as a worked example.

### I/O model: feed bytes in, get bytes out

The library never reads a clock or RNG, never opens a socket, never
spawns a thread. Each call takes `Now` (your monotonic + wall clock
reading) and `&mut dyn EntropySource` (your CSPRNG), and writes any
output into a buffer you provide. Wire it up like this:

```rust,ignore
// One Tunnel per peer; one socket per interface.
loop {
    select! {
        (datagram, src) = socket.recv_from() => {
            match tunnel.decapsulate(now(), &encode(src), under_load(),
                                     &datagram, &mut out, &mut rng)? {
                Received::Data(p)  => deliver_to_tun(trim_padding(p)),
                Received::Reply(w) => socket.send_to(w, src)?,
                Received::HandshakeComplete => drain_send_queue(),
                _ => {}
            }
        }
        packet = tun.recv() => {
            match tunnel.encapsulate(now(), &packet, &mut out, &mut rng)? {
                Encapsulated::Transport(w) => socket.send_to(w, peer_addr)?,
                Encapsulated::HandshakeInitiation(w) => {
                    queue_for_retry(packet);     // not consumed yet
                    socket.send_to(w, peer_addr)?;
                }
            }
        }
        _ = sleep_until(tunnel.next_wake()) => {
            while let PollOutput::Send(w, _) =
                    tunnel.poll(now(), &mut out, &mut rng)? {
                socket.send_to(w, peer_addr)?;
            }
        }
    }
}
```

BoringTun bundles the clock (`Instant::now()`), RNG (`OsRng`), and a
256-packet send queue inside `Tunn`; here you own all three, which is
what makes every timer state reachable from a unit test.

### Driving the timers: `poll()` + `next_wake()`

Call `poll()` in a loop until it returns `Idle` whenever
`next_wake()`'s instant arrives **or** after any `encapsulate` /
`decapsulate` call (state changes can arm new timers). `next_wake()`
returning `None` means nothing is armed — sleep until the next packet.

BoringTun has no `next_wake()`: callers tick `update_timers()` on a
fixed cadence (typically once per second). You can do the same here
(just call `poll()` every second and ignore `next_wake()`), but
`next_wake()` lets battery-/tickless-sensitive embedders sleep exactly.

### Handshake rate limiting

WireGuard's design lets anyone who knows your *public* key force one
X25519 per handshake message when `under_load == false` (~50 µs/packet
on this machine). The library has no per-IP state, so it cannot
rate-limit for you. You must:

1. **Decide `under_load`.** BoringTun's heuristic is dead simple and
   works: count handshake-type datagrams (types 1 and 2) in a 1-second
   window; if the count exceeds a small limit (BoringTun defaults to
   **10**), pass `under_load = true`. The library then answers with a
   cheap cookie reply (~5 µs) instead of doing the DH.
2. **Additionally** apply a per-source-IP token bucket *before*
   `decapsulate()`, because a real attacker at a routable IP can
   complete the cookie dance and then flood with valid `mac2`. The
   kernel uses ~20 handshakes/s/IP with a small burst.

Type 4 (transport data) needs no rate limiting: forged transport is
rejected in ~20 ns by the replay-window pre-check.

### Cookie binding: the `remote` argument

`decapsulate()`'s `remote: &[u8]` is the cookie's IP-ownership token —
pass a stable encoding of the **source address you received the
datagram from**. The kernel uses IP+port; BoringTun uses IP only;
either is spec-compliant. What matters is that it's *consistent*: a
cookie minted for `remote = X` only validates `mac2` on a later
message that arrives with `remote = X`. Typical:

```rust,ignore
fn encode(addr: SocketAddr) -> [u8; 18] {
    let mut b = [0u8; 18];
    match addr.ip() {
        IpAddr::V4(a) => b[..4].copy_from_slice(&a.octets()),
        IpAddr::V6(a) => b[..16].copy_from_slice(&a.octets()),
    }
    b[16..].copy_from_slice(&addr.port().to_be_bytes());
    b
}
```

If you prefer one cookie secret per *interface* rather than per
`Tunnel` (as the kernel and BoringTun do), the protocol allows it, but
this crate's per-`Tunnel` jar is strictly more restrictive and needs
no extra wiring.

### Multi-peer demultiplexing and session indices

One `Tunnel` = one peer. For an interface with N peers, keep
`HashMap<u32, PeerId>` from session index to peer, and route incoming
datagrams with `peek()`:

```rust,ignore
match peek(&datagram)? {
    PacketKind::TransportData { receiver_index, .. }
    | PacketKind::HandshakeResponse { receiver_index, .. }
    | PacketKind::CookieReply { receiver_index } => {
        let peer = index_map.get(&receiver_index)?;
        peer.tunnel.decapsulate(...)
    }
    PacketKind::HandshakeInitiation { .. } => {
        // The initiator's identity is encrypted; try the tunnel(s)
        // whose mac1 verifies. With one peer that's trivial; with
        // many, mac1 is keyed only by *your* pubkey so it can't
        // route — process via any tunnel and let UnknownPeer sort
        // it (or, like the kernel, decrypt the static key once and
        // look it up).
    }
}
```

Indices are random 32-bit per session. Update `index_map` whenever a
handshake completes (`Received::HandshakeComplete` / `Received::Reply`
of type 2) or `PollOutput::SessionsExpired` fires. BoringTun instead
embeds a 24-bit peer ID in the upper bits of the index so the map is
implicit; you can do the same by intercepting the index after
`peek()` if you control both ends, but random indices match the
kernel.

### Queuing packets while no session exists

`encapsulate()` returns `HandshakeInitiation` (or `Err(NotEstablished)`)
when there is no usable session — **the payload is not consumed**. The
library does not queue it. If you want BoringTun-style behaviour
(buffer up to 256 packets and flush on handshake completion), keep a
small `VecDeque` yourself and drain it on `Received::HandshakeComplete`.

```sh
cargo test                                        # everything, < 1 s
cargo test --release --test constant_time -- --ignored   # timing tripwires
scripts/coverage.sh                               # coverage table
scripts/check_no_panic.sh                         # object-code panic scan
scripts/fuzz_all.sh 120                           # 6 × 120 s guided fuzz
scripts/interop_wg_tool.sh 64                     # vs wireguard-tools
cargo run --release --example perf                # benchmarks
```

## Performance

Measured by `examples/perf.rs` on this machine (x86_64, single core,
safe/serial code — no SIMD, no unsafe):

```
blake2s-256 (1 KiB)                          665 MB/s
chacha20 keystream (1 KiB)                   860 MB/s
poly1305 (1 KiB)                            2549 MB/s
chacha20poly1305 seal (1 KiB)                619 MB/s
x25519 scalar mult                         41269 op/s   (24.2 µs)
full 1-RTT handshake (both sides)           2815 /s     (355 µs)
encapsulate only (1420 B)                    607 MB/s   (≈ 4.9 Gbit/s)
decapsulate only (1420 B)                    602 MB/s
```

For profiling: `cargo build --profile profiling --example perf`, then
`perf record --call-graph dwarf -- target/profiling/examples/perf`.

## Security model & limitations

* **Entropy is the caller's responsibility** (`EntropySource`): feed it
  OS randomness; everything rests on it.
* The whitepaper's per-IP token-bucket rate limiter and multi-peer
  cryptokey routing are embedder concerns (they require allocation).

WireGuard is a registered trademark of Jason A. Donenfeld. This crate is an
independent implementation of the published protocol and is not affiliated
with or endorsed by the WireGuard project.

## License

MIT OR Apache-2.0.
