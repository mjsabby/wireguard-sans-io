//! Performance and profiling harness (dependency-free).
//!
//! ```text
//! cargo run --release --example perf            # full run
//! cargo run --release --example perf -- --quick # CI smoke numbers
//! ```
//!
//! For profiling with full symbols:
//!
//! ```text
//! cargo build --profile profiling --example perf
//! perf record --call-graph dwarf -- target/profiling/examples/perf
//! perf report
//! ```
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::unreachable
)]

use std::hint::black_box;
use std::time::Instant;

use std::net::SocketAddr;

use wireguard_sans_io::crypto::{aead, blake2s, chacha20, poly1305, siphash, x25519};
use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{
    Device, Encapsulated, Incoming, PeerConfig, PeerId, PollOutput, Received, StaticSecret, Ticks,
    Tunnel, WallClock,
};

fn now(mono: u64) -> Ticks {
    Ticks::from_nanos(mono)
}

// Built, not parsed: these are called inside the timed loops, where
// parsing a string would be a fifth of what routing a datagram costs.
fn a_addr() -> SocketAddr {
    SocketAddr::from(([192, 0, 2, 1], 51820))
}

fn b_addr() -> SocketAddr {
    SocketAddr::from(([192, 0, 2, 2], 51820))
}

/// One endpoint: a device and its single tunnel.
struct Side {
    device: Device,
    tunnel: Tunnel,
}

impl Side {
    fn new(
        key: StaticSecret,
        peer: wireguard_sans_io::PublicKey,
        peer_addr: SocketAddr,
        rng: &mut DeterministicRng,
    ) -> Self {
        let wall = WallClock::new(Ticks::ZERO, 1_700_000_000, 0);
        let device = Device::new(key, wall, rng).unwrap();
        let mut cfg = PeerConfig::new(peer);
        cfg.endpoint = Some(peer_addr);
        let tunnel = device.tunnel(PeerId::new(0).unwrap(), cfg, rng).unwrap();
        Self { device, tunnel }
    }

    /// Deliver a datagram (decrypting transport data in place).
    fn deliver<'a>(
        &mut self,
        t: Ticks,
        from: SocketAddr,
        datagram: &'a mut [u8],
        out: &'a mut [u8],
        rng: &mut DeterministicRng,
    ) -> Received<'a> {
        self.device
            .receive_for(&mut self.tunnel, t, from, false, datagram, out, rng)
            .unwrap()
            .received
    }

    fn poll(&mut self, t: Ticks, rng: &mut DeterministicRng) -> Vec<u8> {
        let mut buf = [0u8; 256];
        match self.tunnel.poll(t, &mut buf, rng).unwrap() {
            PollOutput::Transmit(tx, _) => tx.datagram.to_vec(),
            other => unreachable!("{other:?}"),
        }
    }
}

/// Measure `f` for ~`target_ms`, returning (iterations, seconds).
fn measure<F: FnMut()>(target_ms: u64, mut f: F) -> (u64, f64) {
    // Calibration pass.
    let t0 = Instant::now();
    let mut calib = 0u64;
    while t0.elapsed().as_millis() < 20 {
        f();
        calib += 1;
    }
    let per_iter = t0.elapsed().as_secs_f64() / calib as f64;
    let iters = ((target_ms as f64 / 1000.0) / per_iter).max(1.0) as u64;
    let t0 = Instant::now();
    for _ in 0..iters {
        f();
    }
    (iters, t0.elapsed().as_secs_f64())
}

fn rate(label: &str, unit: &str, target_ms: u64, f: impl FnMut()) {
    let (iters, secs) = measure(target_ms, f);
    let per_sec = iters as f64 / secs;
    let us = secs / iters as f64 * 1e6;
    println!("{label:<46} {per_sec:>12.0} {unit}/s  ({us:>9.2} µs/{unit})");
}

fn throughput(label: &str, bytes_per_iter: usize, target_ms: u64, f: impl FnMut()) {
    let (iters, secs) = measure(target_ms, f);
    let mbps = iters as f64 * bytes_per_iter as f64 / secs / 1e6;
    println!(
        "{label:<46} {mbps:>12.1} MB/s   ({:>9.2} µs/op)",
        secs / iters as f64 * 1e6
    );
}

fn established_pair(rng: &mut DeterministicRng) -> (Side, Side) {
    let a_key = StaticSecret::generate(rng).unwrap();
    let b_key = StaticSecret::generate(rng).unwrap();
    let a_pub = a_key.public_key();
    let b_pub = b_key.public_key();
    let mut a = Side::new(a_key, b_pub, b_addr(), rng);
    let mut b = Side::new(b_key, a_pub, a_addr(), rng);
    let t = now(0);
    let mut out = [0u8; 128];
    a.tunnel.request_handshake(t);
    let mut init = a.poll(t, rng);
    let mut resp = match b.deliver(t, a_addr(), &mut init, &mut out, rng) {
        Received::HandshakeResponse(tx) => tx.datagram.to_vec(),
        _ => unreachable!(),
    };
    let mut out = [0u8; 128];
    assert!(matches!(
        a.deliver(t, b_addr(), &mut resp, &mut out, rng),
        Received::HandshakeComplete
    ));
    // A's confirming keepalive makes the session usable for B too.
    let mut confirm = a.poll(t, rng);
    assert!(matches!(
        b.deliver(t, a_addr(), &mut confirm, &mut out, rng),
        Received::Keepalive
    ));
    (a, b)
}

fn main() {
    let quick = std::env::args().any(|a| a == "--quick");
    let ms = if quick { 60 } else { 400 };
    let mut rng = DeterministicRng::new(0xbe7c);

    println!("== crypto primitives ==");
    let key = [0x42u8; 32];
    let data_1k = [0xa5u8; 1024];
    let data_64 = [0xa5u8; 64];

    throughput("blake2s-256 (1 KiB)", 1024, ms, || {
        black_box(blake2s::hash(&[&data_1k]));
    });
    throughput("chacha20 keystream (1 KiB)", 1024, ms, {
        let mut buf = data_1k;
        move || chacha20::xor_in_place(&key, 0, &[0u8; 12], black_box(&mut buf))
    });
    throughput("poly1305 (1 KiB)", 1024, ms, || {
        black_box(poly1305::poly1305(&key, &data_1k));
    });
    rate("siphash-2-4 (8 B, index codec round)", "op", ms, || {
        black_box(siphash::siphash24(&[7u8; 16], black_box(&[1u8; 8])));
    });
    throughput("chacha20poly1305 seal (1 KiB)", 1024, ms, {
        let mut out = [0u8; 1024 + 16];
        move || {
            aead::seal(&key, &aead::nonce_from_counter(1), &[], &data_1k, &mut out).unwrap();
        }
    });
    throughput("chacha20poly1305 seal (64 B)", 64, ms, {
        let mut out = [0u8; 64 + 16];
        move || {
            aead::seal(&key, &aead::nonce_from_counter(1), &[], &data_64, &mut out).unwrap();
        }
    });
    let scalar = x25519::clamp_scalar([7u8; 32]);
    let point = x25519::x25519_base(&[9u8; 32]);
    rate("x25519 scalar mult", "op", ms, || {
        black_box(x25519::x25519(&scalar, &point));
    });

    println!("\n== handshake ==");
    rate(
        "full 1-RTT handshake (both sides, incl. setup)",
        "handshake",
        ms,
        || {
            let (a, b) = established_pair(&mut rng);
            black_box((a.tunnel, b.tunnel));
        },
    );

    println!("\n== routing ==");
    {
        // What `Device::receive` costs for a transport datagram: parse the
        // header and decode the receiver index to a peer id. No table.
        let (mut a, mut b) = established_pair(&mut rng);
        let mut wire = vec![0u8; 256];
        let n = match a
            .tunnel
            .encapsulate(now(1), &[0xddu8; 64], &mut wire)
            .unwrap()
        {
            Encapsulated::Transport(tx) => tx.datagram.len(),
            _ => unreachable!(),
        };
        rate(
            "device.receive: route a transport datagram",
            "op",
            ms,
            || match b
                .device
                .receive(now(1), a_addr(), false, black_box(&mut wire[..n]))
            {
                Incoming::ForPeer(id, _) => {
                    black_box(id);
                }
                _ => unreachable!(),
            },
        );
    }

    println!("\n== transport ==");
    for (label, size) in [("64 B", 64usize), ("1420 B (typical MTU)", 1420)] {
        let (mut a, mut b) = established_pair(&mut rng);
        let payload = vec![0xddu8; size];
        let mut wire = vec![0u8; size + 64];
        let mut out = [0u8; 128];
        let mut mono = 1_000_000u64;
        throughput(&format!("encapsulate+receive ({label})"), size, ms, {
            let rng = &mut rng;
            move || {
                mono += 1000;
                let t = now(mono);
                let n = match a.tunnel.encapsulate(t, &payload, &mut wire).unwrap() {
                    Encapsulated::Transport(tx) => tx.datagram.len(),
                    _ => unreachable!(),
                };
                // Routed by the device, decrypted in place by the tunnel.
                match b.deliver(t, a_addr(), &mut wire[..n], &mut out, rng) {
                    Received::Data(d) => {
                        black_box(d);
                    }
                    _ => unreachable!(),
                }
            }
        });
    }

    {
        let (mut a, _b) = established_pair(&mut rng);
        let payload = vec![0xddu8; 1420];
        let mut wire = vec![0u8; 2048];
        let mut mono = 1_000_000u64;
        throughput("encapsulate only (1420 B)", 1420, ms, move || {
            mono += 1000;
            match a
                .tunnel
                .encapsulate(now(mono), &payload, &mut wire)
                .unwrap()
            {
                Encapsulated::Transport(tx) => {
                    black_box(tx.datagram);
                }
                _ => unreachable!(),
            }
        });
    }
    {
        // The zero-copy send path: the payload is already in the buffer,
        // 16 bytes in.
        let (mut a, _b) = established_pair(&mut rng);
        let mut wire = vec![0xddu8; 2048];
        let mut mono = 1_000_000u64;
        throughput("encapsulate_in_place only (1420 B)", 1420, ms, move || {
            mono += 1000;
            match a
                .tunnel
                .encapsulate_in_place(now(mono), &mut wire, 1420)
                .unwrap()
            {
                Encapsulated::Transport(tx) => {
                    black_box(tx.datagram);
                }
                _ => unreachable!(),
            }
        });
    }
    {
        // Receive-only: pre-encrypt a batch, then time routing plus
        // in-place decryption.
        let (mut a, mut b) = established_pair(&mut rng);
        let payload = vec![0xddu8; 1420];
        let mut batch = Vec::new();
        let mut mono = 1_000_000u64;
        for _ in 0..200_000 {
            mono += 1000;
            let mut w = vec![0u8; 2048];
            let n = match b.tunnel.encapsulate(now(mono), &payload, &mut w).unwrap() {
                Encapsulated::Transport(tx) => tx.datagram.len(),
                _ => unreachable!(),
            };
            w.truncate(n);
            batch.push(w);
        }
        // A packet can be received once, so every timed iteration needs
        // one of its own. If the machine is fast enough to use them all
        // up, the iterations after that would do nothing and the figure
        // would be too good: say so instead of printing it.
        let next = std::cell::Cell::new(0usize);
        let ran_out = std::cell::Cell::new(false);
        let mut out = [0u8; 128];
        let (iters, secs) = measure(ms.min(150), {
            let rng = &mut rng;
            let (next, ran_out) = (&next, &ran_out);
            move || match batch.get_mut(next.get()) {
                Some(datagram) => {
                    let _ = a.deliver(now(mono), b_addr(), datagram, &mut out, rng);
                    next.set(next.get() + 1);
                }
                None => ran_out.set(true),
            }
        });
        if ran_out.get() {
            println!(
                "{:<46} not measured: {} prepared packets were not enough",
                "receive only (1420 B)",
                next.get()
            );
        } else {
            println!(
                "{:<46} {:>12.1} MB/s   ({:>9.2} µs/op)",
                "receive only (1420 B)",
                iters as f64 * 1420.0 / secs / 1e6,
                secs / iters as f64 * 1e6
            );
        }
    }

    // (That the library allocates nothing is not measured here: it cannot,
    // and scripts/check_no_std.sh shows it by linking it without an
    // allocator.)
    println!("\n(all buffers are the caller's: on the stack, or owned by this program)");
}
