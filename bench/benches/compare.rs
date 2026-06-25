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
//!     decrypt it at B. Dominated by ChaCha20-Poly1305.
//!   * `encapsulate_only/<impl>/<len>`, `decapsulate_only/<impl>/<len>`
//!     — the two halves separately (decap input pre-recorded so the
//!     replay window doesn't reject re-runs; see note in the body).
//!
//! Run with:
//!   cargo bench -p wireguard-bench
//!
//! `wireguard-go` is a Go binary and cannot be linked in-process; for an
//! apples-to-apples number, use the UDP-loopback harness in
//! `bench/src/udp_throughput.rs` against a `wireguard-go` userspace
//! interface and against `wireguard-embed`'s own `udp_throughput`
//! responder mode — both then include identical syscall overhead.

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
                TunnResult::WriteToNetwork(w) => criterion::black_box(w.len()),
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
    // For decapsulate-only, the replay window rejects repeated counters.
    // wireguard-embed: pre-record N distinct ciphertexts and cycle.
    // BoringTun: same. Fair: both pay the same vec lookup per iter.
    const N: usize = 4096;
    let mut g = c.benchmark_group("decapsulate_only");
    for &len in &[64usize, 1280, 1350, 1420] {
        let fx = Fixture::new(len);
        g.throughput(Throughput::Bytes(len as u64));

        // ----- wireguard-embed ------------------------------------------------
        {
            use wireguard_embed::TunnResult;
            // The replay window rejects repeated counters, so each batch
            // gets a fresh pair + N pre-recorded ciphertexts; criterion
            // amortizes the setup over N iterations so it doesn't skew
            // the per-packet number.
            g.bench_with_input(
                BenchmarkId::new("wireguard-embed", len),
                &fx,
                move |b, fx| {
                    b.iter_batched_ref(
                        || {
                            let mut ep = EmbedPair::new(fx);
                            let wires: Vec<Vec<u8>> = (0..N)
                                .map(|_| match ep.a.encapsulate(&fx.packet, &mut ep.buf_a) {
                                    TunnResult::WriteToNetwork(w) => w.to_vec(),
                                    r => panic!("{r:?}"),
                                })
                                .collect();
                            (ep, wires, 0usize)
                        },
                        |(ep, wires, i)| {
                            let wire = &wires[*i % N];
                            *i += 1;
                            match ep.b.decapsulate(None, wire, &mut ep.buf_b) {
                                TunnResult::WriteToTunnel(d) => criterion::black_box(d.len()),
                                r => panic!("{r:?}"),
                            }
                        },
                        criterion::BatchSize::NumIterations(N as u64),
                    );
                },
            );
        }

        // ----- boringtun ------------------------------------------------------
        {
            use boringtun::noise::TunnResult;
            g.bench_with_input(BenchmarkId::new("boringtun", len), &fx, move |b, fx| {
                b.iter_batched_ref(
                    || {
                        let mut bp = BoringPair::new(fx);
                        let wires: Vec<Vec<u8>> = (0..N)
                            .map(|_| match bp.a.encapsulate(&fx.packet, &mut bp.buf_a) {
                                TunnResult::WriteToNetwork(w) => w.to_vec(),
                                r => panic!("{r:?}"),
                            })
                            .collect();
                        (bp, wires, 0usize)
                    },
                    |(bp, wires, i)| {
                        let wire = &wires[*i % N];
                        *i += 1;
                        match bp.b.decapsulate(None, wire, &mut bp.buf_b) {
                            TunnResult::WriteToTunnelV4(d, _)
                            | TunnResult::WriteToTunnelV6(d, _) => criterion::black_box(d.len()),
                            r => panic!("{r:?}"),
                        }
                    },
                    criterion::BatchSize::NumIterations(N as u64),
                );
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
