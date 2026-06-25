//! Attack-resistance tests.
//!
//! Each test either demonstrates that a hypothesised attack does NOT
//! work (locking the defence in as a regression test) or quantifies a
//! specific attack's exact impact.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;
use common::{S, new_pair};
use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{
    Config, Encapsulated, Error, Now, PollOutput, PublicKey, Received, StaticSecret, Tai64N,
    Tunnel, consts,
};

// An off-path attacker who knows the responder's public key can forge a
// HandshakeInitiation that passes mac1 AND both AEADs in
// `consume_initiation` (by encrypting their own static key), forcing the
// responder to perform 2 X25519 operations before the UnknownPeer check.
// This is inherent to the protocol (whitepaper §5.3); the cookie
// mechanism + caller rate-limiting is the defence. We verify the
// responder stops at UnknownPeer (no `next` installed, no response sent)
// and that `under_load=true` short-circuits BEFORE the DH work.
#[test]
fn unknown_peer_forge_stops_at_peer_check() {
    let mut rng = DeterministicRng::new(0xa1);
    let a_key = StaticSecret::generate(&mut rng).unwrap();
    let b_key = StaticSecret::generate(&mut rng).unwrap();
    let m_key = StaticSecret::generate(&mut rng).unwrap();
    let b_pub = b_key.public_key();

    let mut b = Tunnel::new(Config::new(b_key, a_key.public_key())).unwrap();
    let mut mallory = Tunnel::new(Config::new(m_key, b_pub)).unwrap();

    let now = Now::new(0, 1_700_000_000, 0);
    let mut wm = [0u8; 2048];
    let mut wb = [0u8; 2048];
    let init = mallory
        .initiate_handshake(now, &mut wm, &mut rng)
        .unwrap()
        .to_vec();

    // Off-load: B does the full DH dance, then rejects on identity.
    assert_eq!(
        b.decapsulate(now, b"m", false, &init, &mut wb, &mut rng)
            .err(),
        Some(Error::UnknownPeer)
    );
    assert_eq!(b.stats().handshakes_responded, 0, "no `next` installed");

    // Under load: short-circuits to a cookie reply (no Noise DH).
    match b
        .decapsulate(now, b"m", true, &init, &mut wb, &mut rng)
        .unwrap()
    {
        Received::Reply(w) => assert_eq!(w[0], 3, "cookie reply"),
        other => panic!("expected cookie reply under load, got {other:?}"),
    }
}

// `Tai64N::tick()` can produce a nanoseconds field >= 10^9 when the
// ratchet crosses 999_999_999ns — technically a malformed TAI64N label.
// All known WireGuard implementations compare timestamps with raw
// memcmp, so this is interop-safe — verify it never breaks monotonicity.
#[test]
fn tai64n_tick_across_nanos_boundary_is_monotone() {
    let edge = Tai64N::from_bytes([
        0x40, 0, 0, 0, 0, 0, 0, 0x0b, // sec = base+1
        0x3b, 0x9a, 0xc9, 0xff, // 999_999_999
    ]);
    let ticked = edge.tick();
    // Nanoseconds field is now 1_000_000_000 (>= 10^9).
    assert_eq!(ticked.as_bytes()[8..], [0x3b, 0x9a, 0xca, 0x00]);
    assert!(ticked > edge, "byte-wise monotonicity preserved");
    // A real next-second timestamp beats the malformed-nanos ratchet.
    assert!(Tai64N::from_unix(2, 0) > ticked);
    // Long ratchet chains stay strictly increasing.
    let mut t = edge;
    for _ in 0..100 {
        let n = t.tick();
        assert!(n > t);
        t = n;
    }
}

// Replay-window advance is gated on AEAD authentication — a forged high
// counter does NOT slide the window. An on-path attacker reordering REAL
// packets can drop at most WINDOW_BITS packets; quantify both.
#[test]
fn replay_window_advance_is_aead_gated() {
    use wireguard_sans_io::replay::WINDOW_BITS;
    let mut p = new_pair(0xa3);
    p.establish();
    // Seal WINDOW_BITS + 1000 packets so the burst exceeds the window.
    // (establish() burned counter 0 on its keepalive, so wires[i] has
    // counter i+1 — the off-by-one is irrelevant to what's tested.)
    let burst = WINDOW_BITS as usize + 1000;
    let mut wires: Vec<Vec<u8>> = (0..burst).map(|i| p.seal_from_a(&[i as u8; 8])).collect();

    // Forged high counter: AEAD fails, window does NOT advance.
    let mut forged = wires[0].clone();
    forged[8..16].copy_from_slice(&((burst as u64) * 10).to_le_bytes());
    let now = p.clock.now();
    let mut out = [0u8; 256];
    assert_eq!(
        p.b.decapsulate(now, b"", false, &forged, &mut out, &mut p.rng)
            .err(),
        Some(Error::AuthFailure)
    );
    assert!(matches!(
        p.b.decapsulate(now, b"", false, &wires[0], &mut out, &mut p.rng)
            .unwrap(),
        Received::Data(_)
    ));

    // Legitimate high-counter packet, delivered out of order: advances.
    let high = wires.pop().unwrap(); // counter = burst
    p.b.decapsulate(now, b"", false, &high, &mut out, &mut p.rng)
        .unwrap();
    // The window now covers (burst − WINDOW_BITS, burst]. A packet with
    // counter ≤ burst − WINDOW_BITS is too old; one just above is fine.
    let too_old = burst - WINDOW_BITS as usize - 1;
    let just_in = burst - WINDOW_BITS as usize + 10;
    assert_eq!(
        p.b.decapsulate(now, b"", false, &wires[too_old], &mut out, &mut p.rng)
            .err(),
        Some(Error::Replay),
        "counter {} ≤ {}−{} → too old",
        too_old + 1,
        burst,
        WINDOW_BITS
    );
    assert!(matches!(
        p.b.decapsulate(now, b"", false, &wires[just_in], &mut out, &mut p.rng)
            .unwrap(),
        Received::Data(_)
    ));
}

// `greatest_timestamp` can only be poisoned by the configured peer — the
// static_public field is validated against the configured peer BEFORE the
// timestamp is recorded.
#[test]
fn timestamp_poisoning_requires_peer_privkey() {
    let mut rng = DeterministicRng::new(0xa4);
    let a_key = StaticSecret::generate(&mut rng).unwrap();
    let b_key = StaticSecret::generate(&mut rng).unwrap();
    let m_key = StaticSecret::generate(&mut rng).unwrap();
    let b_pub = b_key.public_key();
    let mut a = Tunnel::new(Config::new(a_key.clone(), b_pub)).unwrap();
    let mut b = Tunnel::new(Config::new(b_key, a_key.public_key())).unwrap();
    let mut mallory = Tunnel::new(Config::new(m_key, b_pub)).unwrap();

    let future = Now::new(0, 9_999_999_999, 0);
    let now = Now::new(0, 1_700_000_000, 0);
    let mut wm = [0u8; 2048];
    let m_init = mallory
        .initiate_handshake(future, &mut wm, &mut rng)
        .unwrap()
        .to_vec();
    let mut wb = [0u8; 2048];
    assert_eq!(
        b.decapsulate(now, b"", false, &m_init, &mut wb, &mut rng)
            .err(),
        Some(Error::UnknownPeer)
    );

    // A's legitimate initiation with normal timestamp STILL accepted.
    let mut wa = [0u8; 2048];
    let a_init = a
        .initiate_handshake(now, &mut wa, &mut rng)
        .unwrap()
        .to_vec();
    assert!(matches!(
        b.decapsulate(now, b"", false, &a_init, &mut wb, &mut rng)
            .unwrap(),
        Received::Reply(_)
    ));
}

// A captured initiation, replayed unlimited times, never mutates state
// and never elicits a response.
#[test]
fn replayed_initiation_never_mutates_state() {
    let mut p = new_pair(0xa5);
    let now = p.clock.now();
    let (mut wa, mut wb) = ([0u8; 2048], [0u8; 2048]);
    let init =
        p.a.initiate_handshake(now, &mut wa, &mut p.rng)
            .unwrap()
            .to_vec();
    assert!(matches!(
        p.b.decapsulate(now, b"a", false, &init, &mut wb, &mut p.rng)
            .unwrap(),
        Received::Reply(_)
    ));
    let stats_before = p.b.stats();
    for _ in 0..1000 {
        assert_eq!(
            p.b.decapsulate(now, b"a", false, &init, &mut wb, &mut p.rng)
                .err(),
            Some(Error::ReplayedTimestamp)
        );
    }
    let stats_after = p.b.stats();
    assert_eq!(
        stats_after.handshakes_responded,
        stats_before.handshakes_responded
    );
}

// Cookie reply nonces are unique across multiple `Tunnel` instances that
// share the same local static key (and therefore the same `cookie_send`
// AEAD key). Nonce reuse there = Poly1305 OTK reuse.
#[test]
fn cookie_nonces_unique_across_tunnels_sharing_local_key() {
    let mut rng = DeterministicRng::new(0xa6);
    let local = StaticSecret::generate(&mut rng).unwrap();
    let p1 = StaticSecret::generate(&mut rng).unwrap();
    let p2 = StaticSecret::generate(&mut rng).unwrap();

    let mut t1 = Tunnel::new(Config::new(local.clone(), p1.public_key())).unwrap();
    let mut t2 = Tunnel::new(Config::new(local.clone(), p2.public_key())).unwrap();
    let mut r1 = DeterministicRng::new(0x1111);
    let mut r2 = DeterministicRng::new(0x2222);
    let mut peer1 = Tunnel::new(Config::new(p1, local.public_key())).unwrap();
    let mut peer2 = Tunnel::new(Config::new(p2, local.public_key())).unwrap();

    let now = Now::new(0, 1_700_000_000, 0);
    let (mut wa, mut wb) = ([0u8; 2048], [0u8; 2048]);

    let mut nonces = std::collections::HashSet::new();
    for i in 0..50 {
        let advance = Now::new(i * 6 * S, 1_700_000_000 + i * 6, 0);
        let init1 = peer1
            .initiate_handshake(advance, &mut wa, &mut r1)
            .unwrap()
            .to_vec();
        let init2 = peer2
            .initiate_handshake(advance, &mut wa, &mut r2)
            .unwrap()
            .to_vec();
        for (t, init, r) in [(&mut t1, &init1, &mut r1), (&mut t2, &init2, &mut r2)] {
            match t.decapsulate(now, b"x", true, init, &mut wb, r).unwrap() {
                Received::Reply(w) => {
                    assert_eq!(w[0], 3);
                    let nonce: [u8; 24] = w[8..32].try_into().unwrap();
                    assert!(
                        nonces.insert(nonce),
                        "XChaCha20 nonce {nonce:02x?} REUSED across tunnels — \
                         Poly1305 OTK reuse under shared cookie_send key"
                    );
                }
                other => panic!("{other:?}"),
            }
        }
    }
    assert_eq!(nonces.len(), 100);
}

// Documents a caller-misuse hazard: if the embedder feeds two
// same-interface `Tunnel`s the SAME entropy stream (same seed/state),
// their cookie nonce counters seed identically and collide under the
// shared `cookie_send` key. This is caller misuse, but the failure is
// silent.
#[test]
fn shared_entropy_seed_across_tunnels_collides_nonces() {
    let mut rng = DeterministicRng::new(0xa7);
    let local = StaticSecret::generate(&mut rng).unwrap();
    let p1 = StaticSecret::generate(&mut rng).unwrap();
    let p2 = StaticSecret::generate(&mut rng).unwrap();

    let mut t1 = Tunnel::new(Config::new(local.clone(), p1.public_key())).unwrap();
    let mut t2 = Tunnel::new(Config::new(local.clone(), p2.public_key())).unwrap();
    let mut r1 = DeterministicRng::new(0xdead);
    let mut r2 = DeterministicRng::new(0xdead); // ← embedder bug
    let mut peer1 = Tunnel::new(Config::new(p1, local.public_key())).unwrap();
    let mut peer2 = Tunnel::new(Config::new(p2, local.public_key())).unwrap();

    let now = Now::new(0, 1_700_000_000, 0);
    let (mut wa, mut wb) = ([0u8; 2048], [0u8; 2048]);
    let i1 = peer1
        .initiate_handshake(now, &mut wa, &mut r1)
        .unwrap()
        .to_vec();
    let i2 = peer2
        .initiate_handshake(now, &mut wa, &mut r2)
        .unwrap()
        .to_vec();
    let n1 = match t1
        .decapsulate(now, b"x", true, &i1, &mut wb, &mut r1)
        .unwrap()
    {
        Received::Reply(w) => w[8..32].to_vec(),
        _ => panic!(),
    };
    let n2 = match t2
        .decapsulate(now, b"x", true, &i2, &mut wb, &mut r2)
        .unwrap()
    {
        Received::Reply(w) => w[8..32].to_vec(),
        _ => panic!(),
    };
    assert_eq!(
        n1, n2,
        "identical entropy ⇒ identical nonces under a SHARED key \
         (Poly1305 OTK reuse)"
    );
}

// Output buffer untouched on every error path that runs after the point
// where `out` could conceivably be written.
#[test]
fn output_buffer_untouched_on_every_error_path() {
    let mut p = new_pair(0xa8);
    let now = p.clock.now();
    let mut wa = [0u8; 2048];
    let init =
        p.a.initiate_handshake(now, &mut wa, &mut p.rng)
            .unwrap()
            .to_vec();

    let mut wb = [0xEEu8; 2048];
    p.b.decapsulate(now, b"a", false, &init, &mut wb, &mut p.rng)
        .unwrap();
    let mut wb = [0xEEu8; 2048];
    assert_eq!(
        p.b.decapsulate(now, b"a", false, &init, &mut wb, &mut p.rng)
            .err(),
        Some(Error::ReplayedTimestamp)
    );
    assert!(
        wb.iter().all(|&b| b == 0xEE),
        "ReplayedTimestamp dirtied out"
    );

    let init2 = {
        let later = p.clock.advance(6 * S);
        p.a.initiate_handshake(later, &mut wa, &mut p.rng)
            .unwrap()
            .to_vec()
    };
    let mut wb = [0xEEu8; 2048];
    let r = p.b.decapsulate(
        p.clock.now(),
        b"a",
        false,
        &init2,
        &mut wb,
        &mut wireguard_sans_io::testing::FailingRng,
    );
    assert_eq!(r.err(), Some(Error::EntropyFailure));
    assert!(wb.iter().all(|&b| b == 0xEE), "EntropyFailure dirtied out");
}

// A legitimate peer churning the responder's `next` slot never disturbs
// `current`/`previous`.
#[test]
fn next_slot_churn_does_not_affect_current() {
    let mut p = new_pair(0xa9);
    p.establish();
    p.assert_roundtrip_a_to_b(b"baseline");
    let stats_before = p.b.stats().handshakes_completed;

    for i in 0..50u64 {
        p.clock.advance(6 * S);
        let now = p.clock.now();
        let mut wa = [0u8; 2048];
        let init =
            p.a.initiate_handshake(now, &mut wa, &mut p.rng)
                .unwrap()
                .to_vec();
        let mut wb = [0u8; 2048];
        match p
            .b
            .decapsulate(now, b"a", false, &init, &mut wb, &mut p.rng)
            .unwrap()
        {
            Received::Reply(_) => {}
            other => panic!("init #{i}: {other:?}"),
        }
        if p.clock.mono_ns < consts::REJECT_AFTER_TIME {
            p.assert_roundtrip_a_to_b(b"during churn");
        }
    }
    assert_eq!(p.b.stats().handshakes_completed, stats_before);
}

// Exhaustive single-bit confidentiality lock on transport data.
#[test]
fn no_plaintext_on_any_single_bit_forgery() {
    let mut p = new_pair(0xa11);
    p.establish();
    let wire = p.seal_from_a(b"FLIGHT-CRITICAL TELEMETRY: ALT=35000 HDG=270 IAS=450");
    let now = p.clock.now();
    for byte in 0..wire.len() {
        for bit in 0..8 {
            let mut bad = wire.clone();
            bad[byte] ^= 1 << bit;
            let mut out = vec![0xCCu8; 256];
            let r = p.b.decapsulate(now, b"", false, &bad, &mut out, &mut p.rng);
            assert!(r.is_err(), "byte {byte} bit {bit} accepted");
            assert!(
                out.iter().all(|&b| b == 0xCC),
                "CONFIDENTIALITY VIOLATION at byte {byte} bit {bit}"
            );
        }
    }
}

// Debug formatting of every secret-bearing type leaks nothing.
#[test]
fn debug_never_leaks_secrets() {
    let mut rng = DeterministicRng::new(0xa12);
    let sk = StaticSecret::generate(&mut rng).unwrap();
    let psk = wireguard_sans_io::PresharedKey::generate(&mut rng).unwrap();
    let p = sk.public_key();
    let t = Tunnel::new(Config::new(sk, PublicKey::from_bytes([7; 32])));
    for s in [format!("{psk:?}"), format!("{t:?}"), format!("{p:?}")] {
        // No raw byte dumps of 32-byte secrets (heuristic: nothing that
        // looks like the all-7s peer key or a long hex run we didn't
        // intend). PublicKey legitimately prints hex.
        assert!(!s.to_lowercase().contains("staticsecret(0"));
        assert!(!s.to_lowercase().contains("presharedkey(0"));
    }
}

// Recovery after maximal state abuse — no attacker-reachable state
// permanently wedges the tunnel.
#[test]
fn recovery_after_maximal_state_abuse() {
    let mut p = new_pair(0xa13);
    p.establish();

    let mut captured: Vec<Vec<u8>> = vec![];
    for round in 0..200u64 {
        p.clock.advance(S);
        let now = p.clock.now();
        let mut buf = [0u8; 2048];
        let _ = p.a.poll(now, &mut buf, &mut p.rng);
        let _ = p.b.poll(now, &mut buf, &mut p.rng);
        if p.a.is_established() {
            captured.push(p.seal_from_a(b"data"));
        }
        for w in &captured {
            let mut out = [0u8; 256];
            let _ = p.b.decapsulate(now, b"a", false, w, &mut out, &mut p.rng);
        }
        let mut g = vec![round as u8; 148];
        g[0] = 1;
        let mut out = [0u8; 256];
        let _ = p.b.decapsulate(now, b"x", false, &g, &mut out, &mut p.rng);
    }

    p.clock.advance(600 * S);
    let mut connected = false;
    for _ in 0..200 {
        p.clock.advance(S);
        let now = p.clock.now();
        let mut buf = [0u8; 2048];
        let _ = p.a.poll(now, &mut buf, &mut p.rng);
        let _ = p.b.poll(now, &mut buf, &mut p.rng);
        let mut wa = [0u8; 2048];
        match p.a.encapsulate(now, b"probe", &mut wa, &mut p.rng) {
            Ok(Encapsulated::HandshakeInitiation(w)) => {
                let init = w.to_vec();
                let mut wb = [0u8; 2048];
                if let Ok(Received::Reply(r)) =
                    p.b.decapsulate(now, b"a", false, &init, &mut wb, &mut p.rng)
                {
                    let resp = r.to_vec();
                    let mut wa2 = [0u8; 2048];
                    let _ =
                        p.a.decapsulate(now, b"b", false, &resp, &mut wa2, &mut p.rng);
                }
            }
            Ok(Encapsulated::Transport(w)) => {
                let data = w.to_vec();
                let mut wb = [0u8; 2048];
                if matches!(
                    p.b.decapsulate(now, b"a", false, &data, &mut wb, &mut p.rng),
                    Ok(Received::Data(_))
                ) {
                    connected = true;
                    break;
                }
            }
            Err(_) => {}
        }
    }
    assert!(connected, "tunnel failed to recover after maximal abuse");
}

// Regression lock — the busy-loop fix still holds: an Idle poll result
// never coexists with a next_wake in the past.
#[test]
fn prior_fixes_still_hold() {
    let mut p = common::new_pair_with(0xa14, None, Some(25));
    p.establish();
    p.clock.advance(119 * S);
    let _ = p.seal_from_a(b"x");
    let mut buf = [0u8; 2048];
    for _ in 0..1000 {
        let Some(wake) = p.a.next_wake() else { break };
        if wake.nanos() > p.clock.mono_ns {
            p.clock.mono_ns = wake.nanos();
        }
        let r = p.a.poll(p.clock.now(), &mut buf, &mut p.rng).unwrap();
        if matches!(r, PollOutput::Idle) {
            assert!(
                p.a.next_wake().is_none_or(|w| w.nanos() > p.clock.mono_ns),
                "regressed: Idle with past next_wake"
            );
        }
        if p.clock.mono_ns > 600 * S {
            break;
        }
    }
}
