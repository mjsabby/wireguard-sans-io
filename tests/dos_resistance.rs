//! DoS and resource-exhaustion tests.
//!
//! These quantify the CPU cost an attacker can impose under various
//! threat models, and verify the documented mitigations actually engage.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stderr
)]

mod common;
use common::new_pair;
use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{
    Config, Error, Now, Received, StaticSecret, Tunnel, consts::HANDSHAKE_INITIATION_LEN,
};

/// THREAT MODEL 1: off-path attacker, knows nothing.
/// Can only send random bytes. Cost to defender: parse + length check.
#[test]
fn dos_off_path_unknown_pubkey_is_cheap() {
    let mut p = new_pair(0xd001);
    p.establish();
    let mut rng = DeterministicRng::new(0xa77a);
    use wireguard_sans_io::EntropySource;

    let now = p.clock.now();
    let mut out = [0u8; 256];
    let t0 = std::time::Instant::now();
    for _ in 0..10_000 {
        let mut garbage = [0u8; 148];
        rng.fill(&mut garbage).unwrap();
        garbage[0] = 1; // type = initiation
        garbage[1] = 0;
        garbage[2] = 0;
        garbage[3] = 0;
        let _ =
            p.b.decapsulate(now, b"x", false, &garbage, &mut out, &mut rng);
    }
    let elapsed = t0.elapsed();
    eprintln!(
        "[DoS-1] 10k random initiations (mac1 fails): {:?} = {:.1} ns/packet",
        elapsed,
        elapsed.as_nanos() as f64 / 10_000.0
    );
    assert_eq!(p.b.stats().mac1_failures, 10_000);
    assert_eq!(p.b.stats().auth_failures, 0, "no expensive work done");
    // Should be << 10µs/packet (just one BLAKE2s MAC).
    assert!(
        elapsed.as_nanos() / 10_000 < 50_000,
        "mac1 rejection is too slow: {:?}/10k",
        elapsed
    );
}

/// THREAT MODEL 2: off-path attacker, knows our PUBLIC key (typical).
/// Can forge mac1. Forces consume_initiation = ≥1 X25519 per packet
/// when NOT under load. Verify under_load engages the cookie defence.
#[test]
fn dos_known_pubkey_forces_x25519_unless_under_load() {
    use wireguard_sans_io::consts::LABEL_MAC1;
    use wireguard_sans_io::crypto::blake2s;

    let mut rng = DeterministicRng::new(0xd002);
    let a_key = StaticSecret::generate(&mut rng).unwrap();
    let b_key = StaticSecret::generate(&mut rng).unwrap();
    let b_pub = b_key.public_key();
    let mut b = Tunnel::new(Config::new(b_key, a_key.public_key())).unwrap();

    let mac1_key = blake2s::hash(&[LABEL_MAC1, b_pub.as_bytes()]);
    let now = Now::new(0, 1_700_000_000, 0);
    let mut out = [0u8; 256];

    // Build a forged initiation: random body, valid mac1, mac2=0.
    let forge = |rng: &mut DeterministicRng| -> [u8; HANDSHAKE_INITIATION_LEN] {
        use wireguard_sans_io::EntropySource;
        let mut msg = [0u8; HANDSHAKE_INITIATION_LEN];
        rng.fill(&mut msg[..116]).unwrap();
        msg[0] = 1;
        msg[1] = 0;
        msg[2] = 0;
        msg[3] = 0;
        let mac1 = blake2s::mac(&mac1_key, &[&msg[..116]]);
        msg[116..132].copy_from_slice(&mac1);
        msg[132..].fill(0);
        msg
    };

    // (a) NOT under load: each forgery passes mac1, costs ≥1 X25519.
    let t0 = std::time::Instant::now();
    for _ in 0..1000 {
        let msg = forge(&mut rng);
        let r = b.decapsulate(now, b"10.0.0.9:1", false, &msg, &mut out, &mut rng);
        assert!(r.is_err());
    }
    let cost_noload = t0.elapsed().as_nanos() / 1000;
    eprintln!(
        "[DoS-2a] forged init, valid mac1, NOT under load: {} ns/packet",
        cost_noload
    );
    assert_eq!(b.stats().mac1_failures, 0, "mac1 was valid");

    // (b) Under load: first forgery primes the cookie jar (entropy draw),
    // subsequent ones get cheap cookie replies (1 BLAKE2s mint + 1
    // XChaCha seal, no X25519).
    let t0 = std::time::Instant::now();
    for _ in 0..1000 {
        let msg = forge(&mut rng);
        let r = b.decapsulate(now, b"10.0.0.9:1", true, &msg, &mut out, &mut rng);
        // Either Reply (cookie) or error — never expensive handshake work.
        match r {
            Ok(Received::Reply(w)) => assert_eq!(w[0], 3, "must be cookie reply"),
            Err(_) => {}
            other => panic!("{other:?}"),
        }
    }
    let cost_load = t0.elapsed().as_nanos() / 1000;
    eprintln!(
        "[DoS-2b] forged init, valid mac1, UNDER LOAD: {} ns/packet",
        cost_load
    );
    // Under-load processing must be MUCH cheaper than not-under-load
    // (no X25519). This is the core DoS mitigation.
    assert!(
        cost_load * 5 < cost_noload,
        "under_load did not significantly reduce per-packet cost: \
         {cost_load}ns under load vs {cost_noload}ns without"
    );
    assert_eq!(
        b.stats().handshakes_responded,
        0,
        "no full handshakes under load with bad mac2"
    );
}

/// THREAT MODEL 3: on-path attacker with a CAPTURED valid packet.
/// Can replay it. Verify each replay is rejected cheaply (pre-AEAD).
#[test]
fn dos_replayed_transport_rejected_pre_aead() {
    let mut p = new_pair(0xd003);
    p.establish();
    let wire = p.seal_from_a(b"hello world");
    p.open_at_b(&wire); // delivered once

    let now = p.clock.now();
    let mut out = [0u8; 256];
    let t0 = std::time::Instant::now();
    for _ in 0..10_000 {
        let r =
            p.b.decapsulate(now, b"x", false, &wire, &mut out, &mut p.rng);
        assert_eq!(r.err(), Some(Error::Replay));
    }
    let elapsed = t0.elapsed();
    eprintln!(
        "[DoS-3] 10k transport replays: {:?} = {:.1} ns/packet",
        elapsed,
        elapsed.as_nanos() as f64 / 10_000.0
    );
    assert_eq!(p.b.stats().replays_dropped, 10_000);
    // Replay rejection happens BEFORE the AEAD: should be very cheap.
    assert!(
        elapsed.as_nanos() / 10_000 < 10_000,
        "replay rejection too slow: {:?}/10k",
        elapsed
    );
}

/// THREAT MODEL 4: on-path attacker reorders captured packets to push
/// the replay window forward, dropping in-flight low-counter packets.
/// This is INHERENT to sliding-window anti-replay; quantify the impact.
#[test]
fn dos_replay_window_reorder_drops_at_most_window_packets() {
    use wireguard_sans_io::replay::WINDOW_BITS;

    let mut p = new_pair(0xd004);
    p.establish();

    // Seal WINDOW_BITS + 1000 packets so the reorder jump exceeds the
    // window by a known amount regardless of WINDOW_BITS.
    let burst = WINDOW_BITS as usize + 1000;
    let wires: Vec<Vec<u8>> = (0..burst)
        .map(|i| p.seal_from_a(format!("packet {i}").as_bytes()))
        .collect();

    // Attacker delivers the LAST packet first.
    let _ = p.open_at_b(wires.last().unwrap());

    // Now deliver the rest in order. Packets within WINDOW_BITS of the
    // last counter are accepted; older ones are dropped as too old.
    let mut dropped = 0;
    let mut delivered = 0;
    let now = p.clock.now();
    let mut out = vec![0u8; 256];
    for wire in &wires[..wires.len() - 1] {
        match p
            .b
            .decapsulate(now, b"x", false, wire, &mut out, &mut p.rng)
        {
            Ok(Received::Data(_)) => delivered += 1,
            Err(Error::Replay) => dropped += 1,
            other => panic!("{other:?}"),
        }
    }
    eprintln!(
        "[DoS-4] reorder attack on {}-packet burst: {} delivered, {} dropped (window={})",
        burst, delivered, dropped, WINDOW_BITS
    );
    // Exactly WINDOW_BITS-1 of the preceding packets are in-window
    // (the last one was already delivered); the rest are dropped.
    assert_eq!(delivered, WINDOW_BITS as usize - 1);
    assert_eq!(dropped, burst - WINDOW_BITS as usize);
    // An on-path attacker can drop ≈ (BDP - 2048) packets per burst by
    // reordering. Kernel uses 8128. For high-BDP aviation links, consider
    // whether 2048 is sufficient.
}

/// Verify Tunnel struct size is fixed (no allocation, bounded memory).
#[test]
fn tunnel_struct_size_is_bounded() {
    let size = std::mem::size_of::<Tunnel>();
    eprintln!("[mem] sizeof(Tunnel) = {} bytes", size);
    // Should be a few KB (3 sessions × replay window + handshake state).
    // Exact size depends on layout; just verify it's bounded and
    // reasonable.
    assert!(size > 0 && size < 16_384, "Tunnel size = {} bytes", size);
}
