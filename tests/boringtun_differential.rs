//! Tests documenting behavioral differences vs BoringTun.
//!
//! BoringTun checks peer identity BETWEEN the two handshake AEADs and uses
//! the precomputed static-static DH; this implementation checks AFTER
//! consume_initiation returns and recomputes ss freshly. The difference:
//! an attacker who knows our public key but holds a *different* static key
//! forces 2 X25519 ops here vs 1 in BoringTun.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stderr
)]

use wireguard_sans_io::consts::LABEL_MAC1;
use wireguard_sans_io::crypto::blake2s;
use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{Config, Error, Now, StaticSecret, Tunnel};

/// A third party who knows the responder's public key but holds a
/// DIFFERENT static key sends a fully-valid initiation (mac1 valid, both
/// AEADs decrypt). BoringTun rejects after 1 X25519 (peer-check between
/// AEADs); this implementation does 2 X25519 + 2 AEAD before the
/// caller-side peer check fires.
#[test]
fn unknown_peer_initiation_x25519_cost() {
    let mut rng = DeterministicRng::new(0xb7d1);
    let a_key = StaticSecret::generate(&mut rng).unwrap(); // configured peer
    let b_key = StaticSecret::generate(&mut rng).unwrap(); // responder
    let m_key = StaticSecret::generate(&mut rng).unwrap(); // attacker (Mallory)
    let b_pub = b_key.public_key();
    let mut b = Tunnel::new(Config::new(b_key, a_key.public_key())).unwrap();
    // Mallory builds a tunnel TO B (knows B's pubkey, uses HER OWN key).
    let mut m = Tunnel::new(Config::new(m_key, b_pub)).unwrap();

    let now = Now::new(0, 1_700_000_000, 0);
    let mut wm = [0u8; 2048];
    let mut wb = [0u8; 2048];
    let init = m
        .initiate_handshake(now, &mut wm, &mut rng)
        .unwrap()
        .to_vec();

    // Time many such forgeries vs random-mac1 garbage to estimate the
    // X25519 count. Random mac1 = ~1 BLAKE2s. Mallory's init = 2 X25519
    // + 2 AEAD + hashing. BoringTun would be ~1 X25519 + 1 AEAD.
    let t0 = std::time::Instant::now();
    for _ in 0..200 {
        let r = b.decapsulate(now, b"m", false, &init, &mut wb, &mut rng);
        assert_eq!(r.err(), Some(Error::UnknownPeer));
    }
    let cost_unknown_peer = t0.elapsed().as_nanos() / 200;

    // Baseline: random body with valid mac1 → 1 X25519 (es) then AEAD fails.
    let mac1_key = blake2s::hash(&[LABEL_MAC1, b_pub.as_bytes()]);
    let mut forged = [0u8; 148];
    use wireguard_sans_io::EntropySource;
    rng.fill(&mut forged[..116]).unwrap();
    forged[0] = 1;
    forged[1..4].fill(0);
    let mac1 = blake2s::mac(&mac1_key, &[&forged[..116]]);
    forged[116..132].copy_from_slice(&mac1);
    forged[132..].fill(0);
    let t0 = std::time::Instant::now();
    for _ in 0..200 {
        let _ = b.decapsulate(now, b"m", false, &forged, &mut wb, &mut rng);
    }
    let cost_one_dh = t0.elapsed().as_nanos() / 200;

    eprintln!(
        "UnknownPeer (full consume_initiation): {} ns/packet",
        cost_unknown_peer
    );
    eprintln!(
        "AuthFailure after es only (1 X25519):   {} ns/packet",
        cost_one_dh
    );
    let ratio = cost_unknown_peer as f64 / cost_one_dh as f64;
    eprintln!("ratio = {ratio:.2}× (BoringTun = ~1×; pre-fix = ~2×)");
    // consume_initiation now checks peer identity between the two AEADs and
    // uses precomputed_ss, so the UnknownPeer path costs ~1 X25519, same as
    // the random-body path. Pre-fix this ratio was ~1.96. Allow generous
    // noise margin (CI).
    assert!(
        ratio < 1.4,
        "UnknownPeer path costs {ratio:.2}× the 1-X25519 \
         baseline; the early-out peer check is not engaging"
    );
}

/// BoringTun keeps TWO in-flight handshake states (previous + current) so
/// a late response to a superseded initiation still completes. This
/// implementation keeps ONE: a response to init1 after init2 was sent is
/// rejected. This is a behavioral (not security) difference.
#[test]
fn single_inflight_drops_late_responses() {
    use wireguard_sans_io::Received;
    let mut rng = DeterministicRng::new(0xb7d2);
    let a_key = StaticSecret::generate(&mut rng).unwrap();
    let b_key = StaticSecret::generate(&mut rng).unwrap();
    let a_pub = a_key.public_key();
    let b_pub = b_key.public_key();
    let mut a = Tunnel::new(Config::new(a_key, b_pub)).unwrap();
    let mut b = Tunnel::new(Config::new(b_key, a_pub)).unwrap();

    let mut wa = [0u8; 2048];
    let mut wb = [0u8; 2048];

    // init1 at t=0, B responds, but resp1 is delayed in the network.
    let now0 = Now::new(0, 1_700_000_000, 0);
    let init1 = a
        .initiate_handshake(now0, &mut wa, &mut rng)
        .unwrap()
        .to_vec();
    let resp1 = match b
        .decapsulate(now0, b"a", false, &init1, &mut wb, &mut rng)
        .unwrap()
    {
        Received::Reply(w) => w.to_vec(),
        other => panic!("{other:?}"),
    };

    // At t=6s, A retransmits via poll → init2 (new index, new ephemeral).
    let now6 = Now::new(6_000_000_000, 1_700_000_006, 0);
    use wireguard_sans_io::PollOutput;
    let init2 = match a.poll(now6, &mut wa, &mut rng).unwrap() {
        PollOutput::Send(w, _) => w.to_vec(),
        other => panic!("expected retransmit at 6s, got {other:?}"),
    };
    assert_ne!(&init1[4..8], &init2[4..8], "indices must differ");

    // resp1 (to the SUPERSEDED init1) finally arrives.
    let r = a.decapsulate(now6, b"b", false, &resp1, &mut wa, &mut rng);
    // BoringTun would accept this (it kept init1 in `previous`).
    // This implementation rejects it: only init2 is in-flight.
    assert_eq!(
        r.err(),
        Some(Error::NoPendingHandshake),
        "this impl drops responses to superseded initiations \
         (BoringTun would accept via its `previous` slot)"
    );
}
