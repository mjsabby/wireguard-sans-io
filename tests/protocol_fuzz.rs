//! Unguided deterministic protocol fuzzing: a randomized state-machine
//! exploration that runs under plain `cargo test` (no nightly, no
//! corpus). The guided libFuzzer twin of this harness lives in
//! `fuzz/fuzz_targets/session_ops.rs`.
//!
//! Two endpoints talk over a hostile simulated network that delays,
//! reorders, duplicates, drops and corrupts datagrams and rewrites their
//! source addresses, while the clock jumps erratically and both sides are
//! polled at arbitrary moments. Invariants:
//!
//! 1. nothing ever panics, and no call reports a local fault;
//! 2. every payload delivered as data is *exactly* one of the payloads the
//!    other side encapsulated (no corruption, no forgery), and no
//!    datagram is ever accepted twice (no replay) — whichever of the two
//!    receive paths, single-call or routed, a delivery takes;
//! 3. a datagram that is dropped leaves its buffer and the output buffer
//!    untouched (checked inside the harness, on every delivery);
//! 4. after every operation, each tunnel's timers equal the reference
//!    model's (`tests/common/timer_model.rs`), and a tunnel that reports
//!    `Idle` has no wake-up due;
//! 5. tunnels always recover: after the storm, with a clean network, a
//!    round-trip always succeeds again.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unreachable
)]

mod common;
use std::collections::VecDeque;
use std::net::SocketAddr;

use common::{Endpoint, S, a_addr, b_addr, fingerprint};
use wireguard_sans_io::EntropySource;
use wireguard_sans_io::testing::DeterministicRng;

/// splitmix64 driving all the *decisions* (kept separate from the
/// tunnels' entropy so the schedule is independent of key material).
struct Driver(u64);
impl Driver {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

/// What an episode exercised, so the suite can check it is not vacuous.
#[derive(Default)]
struct Coverage {
    delivered: u64,
    handshakes: u64,
    dropped_forgeries: u64,
    replays: u64,
    cookies: u64,
    roamed: bool,
}

fn run_episode(seed: u64) -> Coverage {
    run_episode_of(seed, 400)
}

fn run_episode_of(seed: u64, steps: u32) -> Coverage {
    let mut drv = Driver(seed);
    // Key material comes from a stream disjoint from the driver's.
    let mut keyrng = DeterministicRng::new(seed ^ 0x6b65_7973);
    let (a_key, a_pub) = common::keypair(&mut keyrng);
    let (b_key, b_pub) = common::keypair(&mut keyrng);
    // Some episodes run with persistent keepalives.
    let ka_a = [None, None, Some(25), Some(3)][drv.below(4) as usize];
    let ka_b = [None, None, Some(25)][drv.below(3) as usize];

    let mut a = Endpoint::new(
        "A",
        common::side(
            a_key,
            b_pub,
            a_addr(),
            Some(b_addr()),
            None,
            ka_a,
            &mut keyrng,
        ),
        ka_a,
        seed.wrapping_mul(3),
    );
    let mut b = Endpoint::new(
        "B",
        common::side(
            b_key,
            a_pub,
            b_addr(),
            Some(a_addr()),
            None,
            ka_b,
            &mut keyrng,
        ),
        ka_b,
        seed.wrapping_mul(5),
    );

    // The hostile network: queues of datagrams in flight.
    let mut to_a: VecDeque<Vec<u8>> = VecDeque::new();
    let mut to_b: VecDeque<Vec<u8>> = VecDeque::new();
    let mut mono: u64 = 0;
    // Addresses datagrams may appear to come from (NAT rebinding).
    let roam = |d: &mut Driver, home: SocketAddr| -> SocketAddr {
        if d.chance(85) {
            home
        } else {
            format!("198.51.100.{}:{}", d.below(4) + 1, 1000 + d.below(3))
                .parse()
                .unwrap()
        }
    };

    let mut roamed_seen = false;
    for _ in 0..steps {
        match drv.below(10) {
            // Send data from A or B.
            0..=2 => {
                let from_a = drv.chance(50);
                let len = drv.below(700) as usize;
                let mut payload = vec![0u8; len];
                let (ep, queue) = if from_a {
                    (&mut a, &mut to_b)
                } else {
                    (&mut b, &mut to_a)
                };
                ep.rng.fill(&mut payload).unwrap();
                if let Some(w) = ep.send(mono, &payload) {
                    queue.push_back(w);
                }
            }
            // Deliver one datagram (possibly corrupted) to its target.
            3..=6 => {
                let deliver_to_a = if to_a.is_empty() {
                    false
                } else if to_b.is_empty() {
                    true
                } else {
                    drv.chance(50)
                };
                let queue = if deliver_to_a { &mut to_a } else { &mut to_b };
                // Pull from a random position: reordering.
                if queue.is_empty() {
                    continue;
                }
                let idx = drv.below(queue.len() as u64) as usize;
                let mut datagram = queue.remove(idx).unwrap();
                // Duplicate sometimes (replay attempts).
                if drv.chance(20) {
                    queue.push_back(datagram.clone());
                }
                // Corrupt sometimes.
                if drv.chance(25) && !datagram.is_empty() {
                    let pos = drv.below(datagram.len() as u64) as usize;
                    datagram[pos] ^= (drv.below(255) + 1) as u8;
                }
                // Truncate sometimes.
                if drv.chance(10) {
                    let keep = drv.below(datagram.len() as u64 + 1) as usize;
                    datagram.truncate(keep);
                }
                let under_load = drv.chance(10);
                let (ep, peer, reply_queue, home) = if deliver_to_a {
                    (&mut a, &b, &mut to_b, b_addr())
                } else {
                    (&mut b, &a, &mut to_a, a_addr())
                };
                let src = roam(&mut drv, home);
                // Half of the deliveries take the two-step routing path.
                let routed = drv.chance(50);
                let (reply, data) = ep.deliver(mono, src, under_load, &datagram, routed);
                roamed_seen |= ep.side.tunnel.endpoint() != Some(home);
                if let Some(d) = data {
                    // INVARIANT: only payloads the peer really sent.
                    assert!(
                        peer.sent.contains(&fingerprint(&d)),
                        "seed {seed}: delivered a payload never sent ({} bytes)",
                        d.len()
                    );
                }
                if let Some(w) = reply {
                    reply_queue.push_back(w);
                }
            }
            // Advance time: small jitter to multi-second jumps.
            7..=8 => {
                mono += match drv.below(5) {
                    0 => drv.below(50 * 1_000_000), // ≤50ms
                    1 => drv.below(2 * S),          // ≤2s
                    2 => drv.below(12 * S),         // ≤12s (crosses REKEY_TIMEOUT)
                    3 => drv.below(40 * S),         // ≤40s
                    _ => drv.below(200 * S),        // ≤200s (crosses REJECT_AFTER_TIME)
                };
            }
            // Poll both sides, routing anything they emit.
            _ => {
                for (ep, queue) in [(&mut a, &mut to_b), (&mut b, &mut to_a)] {
                    queue.extend(ep.poll_to_idle(mono));
                }
            }
        }
        // Network capacity bound (drops happen implicitly when an episode
        // ends with queued datagrams).
        while to_a.len() > 64 {
            to_a.pop_front();
        }
        while to_b.len() > 64 {
            to_b.pop_front();
        }
    }

    // RECOVERY INVARIANT: clean network, generous time → traffic flows.
    to_a.clear();
    to_b.clear();
    mono += 600 * S; // far past every give-up/discard timer
    let mut delivered_after_storm = false;
    for round in 0..2400 {
        // A keeps trying to send; everything is delivered faithfully.
        let mut wires: VecDeque<(bool, Vec<u8>)> = VecDeque::new(); // (to_b, datagram)
        if let Some(w) = a.send(mono, b"recovery probe") {
            wires.push_back((true, w));
        }
        wires.extend(a.poll_to_idle(mono).into_iter().map(|w| (true, w)));
        wires.extend(b.poll_to_idle(mono).into_iter().map(|w| (false, w)));
        while let Some((to_b_side, datagram)) = wires.pop_front() {
            let (ep, src) = if to_b_side {
                (&mut b, a_addr())
            } else {
                (&mut a, b_addr())
            };
            let (reply, data) = ep.deliver(mono, src, false, &datagram, round % 2 == 1);
            if let Some(w) = reply {
                wires.push_back((!to_b_side, w));
            }
            if to_b_side && data.is_some_and(|d| d.starts_with(b"recovery probe")) {
                delivered_after_storm = true;
            }
        }
        if delivered_after_storm {
            break;
        }
        mono += S; // 1s per round: lets pacing/retransmit timers run
        assert!(
            round < 2399,
            "seed {seed}: tunnels failed to recover after the storm"
        );
    }
    assert!(delivered_after_storm);
    // With the network clean, both sides know where the other really is.
    assert_eq!(b.side.tunnel.endpoint(), Some(a_addr()));
    let (sa, sb) = (a.side.tunnel.stats(), b.side.tunnel.stats());
    Coverage {
        delivered: a.delivered + b.delivered,
        handshakes: sa.handshakes_completed + sb.handshakes_completed,
        dropped_forgeries: sa.auth_failures
            + sb.auth_failures
            + a.side.device.stats().mac1_failures
            + b.side.device.stats().mac1_failures,
        replays: sa.replays_dropped + sb.replays_dropped,
        cookies: sa.cookies_received + sb.cookies_received,
        roamed: roamed_seen,
    }
}

#[test]
fn protocol_storm_episodes() {
    // 64 deterministic episodes × 400 hostile steps + recovery check.
    let mut total = Coverage::default();
    for seed in 0..64 {
        let c = run_episode(seed * 0x9e37 + 7);
        total.delivered += c.delivered;
        total.handshakes += c.handshakes;
        total.dropped_forgeries += c.dropped_forgeries;
        total.replays += c.replays;
        total.cookies += c.cookies;
        total.roamed |= c.roamed;
    }
    // The storm must actually have exercised the protocol: data flowed,
    // sessions were (re)established, forgeries and replays were dropped,
    // cookies were exchanged, endpoints moved.
    assert!(total.delivered > 1000, "delivered {}", total.delivered);
    assert!(total.handshakes > 200, "handshakes {}", total.handshakes);
    assert!(
        total.dropped_forgeries > 200,
        "forgeries {}",
        total.dropped_forgeries
    );
    assert!(total.replays > 100, "replays {}", total.replays);
    assert!(total.cookies > 5, "cookies {}", total.cookies);
    assert!(total.roamed);
}

/// One episode a hundred times as long as the others: state that only
/// builds up over many sessions (index rounds, timestamps, counters,
/// cookies that expire and are minted again) under the same storm and the
/// same invariants.
#[test]
fn protocol_storm_long_episode() {
    let c = run_episode_of(0xdead_beef, 40_000);
    // Long means long: hundreds of sessions, not the handful of a short
    // episode. (This seed: 762 handshakes, 2237 payloads delivered, 2280
    // forgeries and 394 replays dropped, 183 cookies.)
    assert!(c.handshakes > 400, "handshakes {}", c.handshakes);
    assert!(c.delivered > 1_200, "delivered {}", c.delivered);
    assert!(
        c.dropped_forgeries > 1_200,
        "forgeries {}",
        c.dropped_forgeries
    );
    assert!(c.replays > 200, "replays {}", c.replays);
    assert!(c.cookies > 50, "cookies {}", c.cookies);
    assert!(c.roamed);
}
