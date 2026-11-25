//! What each kind of datagram costs the receiver, one scenario per run so
//! that `perf stat` counts exactly one thing.
//!
//!   attack_cost <scalar|simd> <scenario> <iters>
//!
//! Prints `iters=<n> ns_per_op=<x>`; the counters come from perf, which
//! `scripts/perf_attack_cost.sh` runs around this for every scenario.
//!
//! Scenarios, by what the sender has to know:
//!
//!   nothing                 garbage, badmac1, unknown-index-for,
//!                           unknown-index-routed, badtag-<bytes>
//!   the public key          cookie-check-cold, cookie-check,
//!                           cookie-required, init-forged, resp-forged
//!                           (and an index seen on the wire)
//!   something recorded      init-replay, replayed
//!   the keys (the peer)     encap-<bytes>, decap-<bytes>, handshake,
//!                           handshake-responder

use std::hint::black_box;
use std::time::Instant;

use wireguard_audit::{
    PerfCtl, addr, established_pair, forged_initiation, forged_response, handshake,
};
use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{
    CryptoProvider, DropReason, Encapsulated, InTree, Incoming, Received, Ticks,
};

type Simd = InTree<wireguard_chacha_simd::Best>;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let provider = args.get(1).map(String::as_str).unwrap_or("scalar");
    let scenario = args.get(2).cloned().unwrap_or_else(|| "garbage".into());
    let iters: u64 = args
        .get(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_000_000);
    match provider {
        "scalar" => run::<InTree>(&scenario, iters),
        "simd" => run::<Simd>(&scenario, iters),
        other => panic!("provider {other}"),
    }
}

fn timed(ctl: &mut PerfCtl, iters: u64, mut f: impl FnMut(u64)) {
    // Warm-up outside the counted region.
    for i in 0..(iters / 50).clamp(1, 20_000) {
        f(i);
    }
    ctl.enable();
    let t0 = Instant::now();
    for i in 0..iters {
        f(i);
    }
    let dt = t0.elapsed();
    ctl.disable();
    println!(
        "iters={iters} ns_per_op={:.2}",
        dt.as_nanos() as f64 / iters as f64
    );
}

fn run<P: CryptoProvider>(scenario: &str, iters: u64) {
    let mut ctl = PerfCtl::new();
    let mut rng = DeterministicRng::new(0xa0d17);
    let now = Ticks::from_nanos(1_000_000);
    let src = addr(1, 51820);
    let mut out = [0u8; 256];

    match scenario {
        // ---- nothing that knows any key ---------------------------------
        "garbage" => {
            let (_a, mut b) = established_pair::<P>(&mut rng);
            let mut d = [0xffu8; 40];
            timed(&mut ctl, iters, |_| {
                let r = b
                    .device
                    .receive_for(
                        &mut b.tunnel,
                        now,
                        src,
                        false,
                        black_box(&mut d),
                        &mut out,
                        &mut rng,
                    )
                    .unwrap();
                assert!(matches!(
                    r.received,
                    Received::Dropped(DropReason::Malformed)
                ));
            });
        }
        "badmac1" => {
            let (_a, mut b) = established_pair::<P>(&mut rng);
            let mut d = forged_initiation(&b.public, &mut rng);
            d[120] ^= 1;
            timed(&mut ctl, iters, |i| {
                d[4..8].copy_from_slice(&(i as u32).to_le_bytes());
                let r = b
                    .device
                    .receive_for(
                        &mut b.tunnel,
                        now,
                        src,
                        false,
                        black_box(&mut d),
                        &mut out,
                        &mut rng,
                    )
                    .unwrap();
                assert!(matches!(
                    r.received,
                    Received::Dropped(DropReason::InvalidMac1)
                ));
            });
        }
        "unknown-index-for" | "unknown-index-routed" => {
            let (_a, mut b) = established_pair::<P>(&mut rng);
            let mut d = [0u8; 96];
            d[0] = 4;
            let routed = scenario.ends_with("routed");
            timed(&mut ctl, iters, |i| {
                d[4..8].copy_from_slice(&(i as u32).wrapping_mul(2_654_435_761).to_le_bytes());
                if routed {
                    match b.device.receive(now, src, false, black_box(&mut d)) {
                        Incoming::ForPeer(id, pkt) => {
                            // The embedder's table lookup would be here.
                            if id.get() == 0 {
                                let r = b.tunnel.handle(now, src, pkt).unwrap();
                                black_box(&r);
                            }
                        }
                        other => panic!("{other:?}"),
                    }
                } else {
                    let r = b
                        .device
                        .receive_for(
                            &mut b.tunnel,
                            now,
                            src,
                            false,
                            black_box(&mut d),
                            &mut out,
                            &mut rng,
                        )
                        .unwrap();
                    black_box(&r);
                }
            });
        }

        // ---- needs the responder's public key ---------------------------
        "cookie-required" | "cookie-check" | "cookie-check-cold" => {
            // Under load. `-cold`: nobody has been sent a cookie yet, so
            // there is no secret a `mac2` could have been made with and
            // nothing to compute. Otherwise there is one, as there is a
            // moment into any flood: `cookie-check` is the two MACs that
            // say this message has no valid cookie, `cookie-required`
            // those and the reply.
            let (_a, mut b) = established_pair::<P>(&mut rng);
            let mut d = forged_initiation(&b.public, &mut rng);
            if scenario != "cookie-check-cold" {
                match b.device.receive(now, src, true, &mut d) {
                    Incoming::CookieRequired(ch) => {
                        b.device.cookie_reply(now, &ch, &mut out, &mut rng).unwrap();
                    }
                    other => panic!("{other:?}"),
                }
            }
            let reply = scenario == "cookie-required";
            timed(&mut ctl, iters, |_| {
                match b.device.receive(now, src, true, black_box(&mut d)) {
                    Incoming::CookieRequired(ch) => {
                        if reply {
                            let tx = b.device.cookie_reply(now, &ch, &mut out, &mut rng).unwrap();
                            black_box(tx.datagram);
                        }
                    }
                    other => panic!("{other:?}"),
                }
            });
        }
        "init-forged" => {
            // Not under load: one X25519 in identify(), then AuthFailure.
            let (_a, mut b) = established_pair::<P>(&mut rng);
            let mut d = forged_initiation(&b.public, &mut rng);
            timed(&mut ctl, iters, |_| {
                let r = b
                    .device
                    .receive_for(
                        &mut b.tunnel,
                        now,
                        src,
                        false,
                        black_box(&mut d),
                        &mut out,
                        &mut rng,
                    )
                    .unwrap();
                assert!(
                    matches!(r.received, Received::Dropped(DropReason::AuthFailure)),
                    "{r:?}"
                );
            });
        }
        "init-replay" => {
            // A genuine initiation of the peer's, recorded and played again.
            let (mut a, mut b) = established_pair::<P>(&mut rng);
            let t = Ticks::from_secs(10);
            a.tunnel.request_handshake(t);
            let init = a.poll(t, &mut rng).expect("initiation");
            let mut first = init.clone();
            let r = b
                .device
                .receive_for(&mut b.tunnel, t, src, false, &mut first, &mut out, &mut rng)
                .unwrap();
            assert!(matches!(r.received, Received::HandshakeResponse(_)));
            let mut d = init.clone();
            let later = Ticks::from_secs(11);
            timed(&mut ctl, iters, |_| {
                let r = b
                    .device
                    .receive_for(
                        &mut b.tunnel,
                        later,
                        src,
                        false,
                        black_box(&mut d),
                        &mut out,
                        &mut rng,
                    )
                    .unwrap();
                assert!(
                    matches!(r.received, Received::Dropped(DropReason::ReplayedTimestamp)),
                    "{r:?}"
                );
            });
        }
        "resp-forged" => {
            // Needs the initiator's public key and the index on the wire.
            let (mut a, _b) = established_pair::<P>(&mut rng);
            let t = Ticks::from_secs(10);
            a.tunnel.request_handshake(t);
            let init = a.poll(t, &mut rng).expect("initiation");
            let index = u32::from_le_bytes(init[4..8].try_into().unwrap());
            let mut d = forged_response(&a.public, index, &mut rng);
            let from = addr(2, 51820);
            timed(&mut ctl, iters, |_| {
                let r = a
                    .device
                    .receive_for(
                        &mut a.tunnel,
                        t,
                        from,
                        false,
                        black_box(&mut d),
                        &mut out,
                        &mut rng,
                    )
                    .unwrap();
                assert!(
                    matches!(r.received, Received::Dropped(DropReason::AuthFailure)),
                    "{r:?}"
                );
            });
        }

        // ---- transport, forged ------------------------------------------
        s if s.starts_with("badtag-") => {
            let len: usize = s["badtag-".len()..].parse().unwrap();
            assert!(len >= 32);
            let (mut a, mut b) = established_pair::<P>(&mut rng);
            let mut genuine = vec![0u8; 128];
            let n = match a
                .tunnel
                .encapsulate(now, &[0xdd; 16], &mut genuine)
                .unwrap()
            {
                Encapsulated::Transport(tx) => tx.datagram.len(),
                other => panic!("{other:?}"),
            };
            assert_eq!(n, 48);
            let mut d = vec![0x5au8; len];
            d[..16].copy_from_slice(&genuine[..16]);
            timed(&mut ctl, iters, |i| {
                // An unseen counter every time (nothing authenticates, so
                // the window never moves).
                d[8..16].copy_from_slice(&(1000 + i).to_le_bytes());
                let r = b
                    .device
                    .receive_for(
                        &mut b.tunnel,
                        now,
                        src,
                        false,
                        black_box(&mut d),
                        &mut out,
                        &mut rng,
                    )
                    .unwrap();
                assert!(
                    matches!(r.received, Received::Dropped(DropReason::AuthFailure)),
                    "{r:?}"
                );
            });
        }
        "replayed" => {
            let (mut a, mut b) = established_pair::<P>(&mut rng);
            let mut genuine = vec![0u8; 1600];
            let n = match a
                .tunnel
                .encapsulate(now, &[0xdd; 1420], &mut genuine)
                .unwrap()
            {
                Encapsulated::Transport(tx) => tx.datagram.len(),
                other => panic!("{other:?}"),
            };
            let recorded = genuine[..n].to_vec();
            let mut first = recorded.clone();
            let r = b
                .device
                .receive_for(
                    &mut b.tunnel,
                    now,
                    src,
                    false,
                    &mut first,
                    &mut out,
                    &mut rng,
                )
                .unwrap();
            assert!(matches!(r.received, Received::Data(_)));
            let mut d = recorded.clone();
            timed(&mut ctl, iters, |_| {
                let r = b
                    .device
                    .receive_for(
                        &mut b.tunnel,
                        now,
                        src,
                        false,
                        black_box(&mut d),
                        &mut out,
                        &mut rng,
                    )
                    .unwrap();
                assert!(
                    matches!(r.received, Received::Dropped(DropReason::Replay)),
                    "{r:?}"
                );
            });
        }

        // ---- the honest paths -------------------------------------------
        s if s.starts_with("encap-") => {
            let len: usize = s["encap-".len()..].parse().unwrap();
            let (mut a, _b) = established_pair::<P>(&mut rng);
            let payload = vec![0xddu8; len];
            let mut wire = vec![0u8; len + 64];
            let mut mono = 1_000_000u64;
            timed(&mut ctl, iters, |_| {
                mono += 1000;
                match a
                    .tunnel
                    .encapsulate(Ticks::from_nanos(mono), black_box(&payload), &mut wire)
                    .unwrap()
                {
                    Encapsulated::Transport(tx) => {
                        black_box(tx.datagram);
                    }
                    other => panic!("{other:?}"),
                }
            });
        }
        s if s.starts_with("decap-") => {
            let len: usize = s["decap-".len()..].parse().unwrap();
            let (mut a, mut b) = established_pair::<P>(&mut rng);
            let payload = vec![0xddu8; len];
            let stride = len + 64;
            let warm = (iters / 50).clamp(1, 20_000);
            let total = (iters + warm) as usize;
            let mut batch = vec![0u8; total * stride];
            let mut n = 0;
            for chunk in batch.chunks_exact_mut(stride) {
                n = match a.tunnel.encapsulate(now, &payload, chunk).unwrap() {
                    Encapsulated::Transport(tx) => tx.datagram.len(),
                    other => panic!("{other:?}"),
                };
            }
            let mut next = 0usize;
            timed(&mut ctl, iters, |_| {
                let d = &mut batch[next * stride..next * stride + n];
                next += 1;
                let r = b
                    .device
                    .receive_for(&mut b.tunnel, now, src, false, d, &mut out, &mut rng)
                    .unwrap();
                match r.received {
                    Received::Data(p) => {
                        black_box(p);
                    }
                    other => panic!("{other:?}"),
                }
            });
        }
        "handshake" => {
            // Both sides of one handshake (no setup), a new one every 6 s
            // of protocol time.
            let (mut a, mut b) = established_pair::<P>(&mut rng);
            let mut secs = 10u64;
            timed(&mut ctl, iters, |_| {
                secs += 6;
                handshake(&mut a, &mut b, Ticks::from_secs(secs), &mut rng);
            });
        }
        "handshake-responder" => {
            // The responder's half only: consume a fresh, genuine
            // initiation and build the response.
            let (mut a, mut b) = established_pair::<P>(&mut rng);
            let warm = (iters / 50).clamp(1, 20_000);
            let total = iters + warm;
            let mut inits = Vec::with_capacity(total as usize);
            let mut secs = 10u64;
            for _ in 0..total {
                secs += 6;
                let t = Ticks::from_secs(secs);
                a.tunnel.request_handshake(t);
                // (An expiry notification may come first.)
                let init = (0..4)
                    .find_map(|_| a.poll(t, &mut rng))
                    .expect("initiation");
                assert_eq!(init.len(), 148);
                inits.push((t, init));
            }
            let mut next = 0usize;
            timed(&mut ctl, iters, |_| {
                let (t, d) = &mut inits[next];
                next += 1;
                let r = b
                    .device
                    .receive_for(&mut b.tunnel, *t, src, false, d, &mut out, &mut rng)
                    .unwrap();
                assert!(
                    matches!(r.received, Received::HandshakeResponse(_)),
                    "{r:?}"
                );
            });
        }
        other => panic!("unknown scenario {other}"),
    }
}
