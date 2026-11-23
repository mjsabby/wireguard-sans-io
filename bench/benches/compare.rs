//! Head-to-head Criterion benchmarks: `wireguard-embed` (this crate's
//! std driver around the no_std core) vs Cloudflare's BoringTun, both
//! exercised through identical handshake + transport flows on identical
//! key material.
//!
//! What's measured:
//!   * `handshake/<impl>` — full 1-RTT Noise IKpsk2 handshake (both
//!     sides), including the confirming keepalive. This is dominated by
//!     X25519 (4 scalar mults).
//!   * `transport_roundtrip/<impl>/<len>` — encrypt one IP packet at A,
//!     decrypt it at B. Dominated by ChaCha20-Poly1305. The extra
//!     `wireguard-embed-in-place` line decrypts in the receive buffer
//!     (no copy, no allocation); BoringTun has no equivalent call.
//!   * `encapsulate_only/<impl>/<len>`, `decapsulate_only/<impl>/<len>`
//!     — the two halves separately, both in the steady state of an
//!     established session (the decapsulate input is recorded in blocks
//!     outside the timed part, so that the replay window never sees a
//!     datagram twice; see the note in the body).
//!
//! Run with:
//!   cargo bench -p wireguard-bench
//!
//! `wireguard-go` is a Go binary and cannot be linked in-process; for an
//! apples-to-apples number, use the UDP-loopback harness in
//! `bench/src/udp_throughput.rs` against a `wireguard-go` userspace
//! interface and against `wireguard-embed`'s own `udp_throughput`
//! responder mode — both then include identical syscall overhead.

use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use wireguard_bench::{
    BoringPair, EmbedPair, Fixture, boring_full_handshake, embed_full_handshake,
};

fn bench_handshake(c: &mut Criterion) {
    let fx = Fixture::new(64);
    let mut g = c.benchmark_group("handshake");
    g.bench_function("wireguard-embed", |b| b.iter(|| embed_full_handshake(&fx)));
    g.bench_function("boringtun", |b| b.iter(|| boring_full_handshake(&fx)));
    g.finish();
}

fn bench_transport_roundtrip(c: &mut Criterion) {
    let mut g = c.benchmark_group("transport_roundtrip");
    for &len in &[64usize, 576, 1280, 1350, 1420] {
        let fx = Fixture::new(len);
        g.throughput(Throughput::Bytes(len as u64));

        let mut ep = EmbedPair::new(&fx);
        g.bench_with_input(BenchmarkId::new("wireguard-embed", len), &fx, |b, fx| {
            b.iter(|| {
                let n = ep.roundtrip(&fx.packet);
                assert_eq!(n, len);
            });
        });

        let mut bp = BoringPair::new(&fx);
        g.bench_with_input(BenchmarkId::new("boringtun", len), &fx, |b, fx| {
            b.iter(|| {
                let n = bp.roundtrip(&fx.packet);
                assert_eq!(n, len);
            });
        });

        // Not a like-for-like line: decrypts in the buffer the datagram
        // was written to, with no copy and no allocation (BoringTun has
        // no such receive call). It is here to show what the copy costs.
        let mut ep = EmbedPair::new(&fx);
        g.bench_with_input(
            BenchmarkId::new("wireguard-embed-in-place", len),
            &fx,
            |b, fx| {
                b.iter(|| {
                    let n = ep.roundtrip_in_place(&fx.packet);
                    assert_eq!(n, len);
                });
            },
        );
    }
    g.finish();
}

fn bench_encapsulate_only(c: &mut Criterion) {
    let mut g = c.benchmark_group("encapsulate_only");
    for &len in &[64usize, 1280, 1350, 1420] {
        let fx = Fixture::new(len);
        g.throughput(Throughput::Bytes(len as u64));

        let mut ep = EmbedPair::new(&fx);
        g.bench_with_input(BenchmarkId::new("wireguard-embed", len), &fx, |b, fx| {
            use wireguard_embed::TunnResult;
            b.iter(|| match ep.a.encapsulate(&fx.packet, &mut ep.buf_a) {
                TunnResult::WriteToNetwork(w, _) => criterion::black_box(w.len()),
                r => panic!("{r:?}"),
            });
        });

        let mut bp = BoringPair::new(&fx);
        g.bench_with_input(BenchmarkId::new("boringtun", len), &fx, |b, fx| {
            use boringtun::noise::TunnResult;
            b.iter(|| match bp.a.encapsulate(&fx.packet, &mut bp.buf_a) {
                TunnResult::WriteToNetwork(w) => criterion::black_box(w.len()),
                r => panic!("{r:?}"),
            });
        });
    }
    g.finish();
}

fn bench_decapsulate_only(c: &mut Criterion) {
    // The replay window rejects a datagram it has seen, so every measured
    // call needs a fresh one — from the *same* session: what is measured
    // is the steady state, packet after packet on an established tunnel.
    //
    // `iter_custom` gets the number of iterations and returns the time
    // they took. A pair is set up once per call; then, block by block, the
    // sender encrypts `BLOCK` datagrams (not timed) and the receiver
    // decrypts them (timed). Both implementations pay the same per-packet
    // slice lookup.
    //
    // (This used `iter_batched_ref`, whose setup runs once per *iteration*:
    // every measured call was the first packet on a brand-new pair — the
    // one that confirms the session — and each of them cost a handshake
    // and thousands of unused datagrams to set up.)
    const BLOCK: u64 = 1024;
    let mut g = c.benchmark_group("decapsulate_only");
    for &len in &[64usize, 1280, 1350, 1420] {
        let fx = Fixture::new(len);
        g.throughput(Throughput::Bytes(len as u64));

        // ----- wireguard-embed ------------------------------------------------
        {
            use wireguard_embed::TunnResult;
            g.bench_with_input(BenchmarkId::new("wireguard-embed", len), &fx, |b, fx| {
                b.iter_custom(|iters| {
                    let mut ep = EmbedPair::new(fx);
                    let mut measured = Duration::ZERO;
                    let mut left = iters;
                    while left > 0 {
                        let block = left.min(BLOCK);
                        let wires: Vec<Vec<u8>> = (0..block)
                            .map(|_| match ep.a.encapsulate(&fx.packet, &mut ep.buf_a) {
                                TunnResult::WriteToNetwork(w, _) => w.to_vec(),
                                r => panic!("{r:?}"),
                            })
                            .collect();
                        let start = Instant::now();
                        for wire in &wires {
                            match ep.b.decapsulate(ep.a_addr, wire, &mut ep.buf_b) {
                                TunnResult::WriteToTunnel(d) => {
                                    criterion::black_box(d.len());
                                }
                                r => panic!("{r:?}"),
                            }
                        }
                        measured += start.elapsed();
                        left -= block;
                    }
                    measured
                });
            });
        }

        // ----- boringtun ------------------------------------------------------
        {
            use boringtun::noise::TunnResult;
            g.bench_with_input(BenchmarkId::new("boringtun", len), &fx, |b, fx| {
                b.iter_custom(|iters| {
                    let mut bp = BoringPair::new(fx);
                    let mut measured = Duration::ZERO;
                    let mut left = iters;
                    while left > 0 {
                        let block = left.min(BLOCK);
                        let wires: Vec<Vec<u8>> = (0..block)
                            .map(|_| match bp.a.encapsulate(&fx.packet, &mut bp.buf_a) {
                                TunnResult::WriteToNetwork(w) => w.to_vec(),
                                r => panic!("{r:?}"),
                            })
                            .collect();
                        let start = Instant::now();
                        for wire in &wires {
                            match bp.b.decapsulate(None, wire, &mut bp.buf_b) {
                                TunnResult::WriteToTunnelV4(d, _)
                                | TunnResult::WriteToTunnelV6(d, _) => {
                                    criterion::black_box(d.len());
                                }
                                r => panic!("{r:?}"),
                            }
                        }
                        measured += start.elapsed();
                        left -= block;
                    }
                    measured
                });
            });
        }
    }
    g.finish();
}

criterion_group!(
    benches,
    bench_handshake,
    bench_transport_roundtrip,
    bench_encapsulate_only,
    bench_decapsulate_only
);
criterion_main!(benches);
