//! DoS and resource-exhaustion tests.
//!
//! These go through the threat models one by one and verify that the
//! documented mitigations engage. What an attacker can make us compute is
//! asserted as an exact count of cryptographic operations (see
//! `common::counting`, and `tests/cost.rs` for the full table); the
//! timings printed along the way are for the reader, never asserted — a
//! busy machine would make such an assertion fail for no reason.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stderr
)]

mod common;
use common::counting::{Counts, spent};
use common::{Rx, new_counting_pair, new_pair, x_addr};
use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{
    Device, DropReason, EntropySource, Tunnel, consts::HANDSHAKE_INITIATION_LEN,
};

/// THREAT MODEL 1: off-path attacker, knows nothing.
/// Can only send random bytes. Cost to defender: parse + one BLAKE2s MAC.
#[test]
fn dos_off_path_unknown_pubkey_is_cheap() {
    let mut p = new_counting_pair(0xd001);
    p.establish();
    let mut rng = DeterministicRng::new(0xa77a);

    let now = p.clock.now();
    let _ = spent();
    let t0 = std::time::Instant::now();
    for _ in 0..10_000 {
        let mut garbage = [0u8; 148];
        rng.fill(&mut garbage).unwrap();
        garbage[0] = 1; // type = initiation
        garbage[1] = 0;
        garbage[2] = 0;
        garbage[3] = 0;
        assert_eq!(
            p.b.recv_from(now, x_addr(), false, &garbage, &mut rng).rx,
            Rx::Dropped(DropReason::InvalidMac1)
        );
    }
    let elapsed = t0.elapsed();
    eprintln!(
        "[DoS-1] 10k random initiations (mac1 fails): {:?} = {:.1} ns/packet",
        elapsed,
        elapsed.as_nanos() as f64 / 10_000.0
    );
    assert_eq!(p.b.device.stats().mac1_failures, 10_000);
    assert_eq!(
        p.b.tunnel.stats().auth_failures,
        0,
        "no expensive work done"
    );
    assert_eq!(
        p.b.device.stats().initiations,
        1,
        "only the genuine handshake"
    );
    assert_eq!(
        p.b.tunnel.stats().auth_failures,
        0,
        "the tunnel never saw them"
    );
    // Exactly one keyed hash per packet, and nothing else at all.
    assert_eq!(
        spent(),
        Counts {
            mac: 10_000,
            ..Counts::default()
        }
    );
}

/// THREAT MODEL 2: off-path attacker, knows our PUBLIC key (typical).
/// Can forge mac1. Forces ONE X25519 per packet when NOT under load.
/// Verify under_load engages the cookie defence.
#[test]
fn dos_known_pubkey_forces_x25519_unless_under_load() {
    use wireguard_sans_io::consts::LABEL_MAC1;
    use wireguard_sans_io::crypto::blake2s;

    let mut p = new_counting_pair(0xd002);
    let mut rng = DeterministicRng::new(0xd002);
    let b_pub = p.b.device.public_key();
    let mac1_key = blake2s::hash(&[LABEL_MAC1, b_pub.as_bytes()]);
    let now = p.clock.now();

    // Build a forged initiation: random body, valid mac1, mac2=0.
    let forge = |rng: &mut DeterministicRng| -> [u8; HANDSHAKE_INITIATION_LEN] {
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

    // (a) NOT under load: each forgery passes mac1, costs one X25519, and
    // dies at the first AEAD.
    let _ = spent();
    let t0 = std::time::Instant::now();
    for _ in 0..1000 {
        let msg = forge(&mut rng);
        assert_eq!(
            p.b.recv_from(now, x_addr(), false, &msg, &mut rng).rx,
            Rx::Dropped(DropReason::AuthFailure)
        );
    }
    let cost_noload = t0.elapsed().as_nanos() / 1000;
    eprintln!(
        "[DoS-2a] forged init, valid mac1, NOT under load: {} ns/packet",
        cost_noload
    );
    assert_eq!(p.b.device.stats().mac1_failures, 0, "mac1 was valid");
    assert_eq!(p.b.device.stats().initiations, 1000);
    assert_eq!(p.b.tunnel.stats().auth_failures, 1000);
    let cost = spent();
    assert_eq!(
        (cost.x25519, cost.x25519_public, cost.open),
        (1000, 0, 1000),
        "one X25519 and one failed AEAD each: {cost:?}"
    );

    // (b) Under load: the first forgery primes the cookie jar (entropy
    // draw), subsequent ones get cheap cookie replies (1 BLAKE2s mint + 1
    // XChaCha seal, no X25519).
    let t0 = std::time::Instant::now();
    for _ in 0..1000 {
        let msg = forge(&mut rng);
        match p.b.recv_from(now, x_addr(), true, &msg, &mut rng).rx {
            Rx::CookieReply(w) => assert_eq!(w[0], 3, "must be cookie reply"),
            other => panic!("{other:?}"),
        }
    }
    let cost_load = t0.elapsed().as_nanos() / 1000;
    eprintln!(
        "[DoS-2b] forged init, valid mac1, UNDER LOAD: {} ns/packet",
        cost_load
    );
    // Under load there is no Diffie-Hellman at all: this is the core DoS
    // mitigation. (The two timings above are printed for the reader.)
    let cost = spent();
    assert_eq!(cost.scalar_mults(), 0, "{cost:?}");
    assert_eq!((cost.open, cost.seal, cost.xseal), (0, 0, 1000), "{cost:?}");
    let _ = (cost_load, cost_noload);
    assert_eq!(p.b.device.stats().initiations, 1000, "no DH under load");
    assert_eq!(p.b.tunnel.stats().auth_failures, 1000, "no DH under load");
    assert_eq!(p.b.device.stats().cookies_sent, 1000);
    assert_eq!(
        p.b.tunnel.stats().handshakes_responded,
        0,
        "no full handshakes under load with bad mac2"
    );
}

/// THREAT MODEL 3: on-path attacker with a CAPTURED valid packet.
/// Can replay it. Verify each replay is rejected cheaply (pre-AEAD).
#[test]
fn dos_replayed_transport_rejected_pre_aead() {
    let mut p = new_counting_pair(0xd003);
    p.establish();
    let wire = p.seal_from_a(b"hello world");
    p.open_at_b(&wire); // delivered once

    let _ = spent();
    let t0 = std::time::Instant::now();
    for _ in 0..10_000 {
        assert_eq!(p.deliver_to_b(&wire).rx, Rx::Dropped(DropReason::Replay));
    }
    let elapsed = t0.elapsed();
    eprintln!(
        "[DoS-3] 10k transport replays: {:?} = {:.1} ns/packet",
        elapsed,
        elapsed.as_nanos() as f64 / 10_000.0
    );
    assert_eq!(p.b.tunnel.stats().replays_dropped, 10_000);
    assert_eq!(p.b.tunnel.stats().auth_failures, 0, "no AEAD was run");
    // Replay rejection happens BEFORE the AEAD: no cryptographic
    // operation of any kind was spent on the ten thousand replays.
    assert_eq!(spent(), Counts::default());
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
    for wire in &wires[..wires.len() - 1] {
        match p.deliver_to_b(wire).rx {
            Rx::Data(_) => delivered += 1,
            Rx::Dropped(DropReason::Replay) => dropped += 1,
            other => panic!("{other:?}"),
        }
    }
    eprintln!(
        "[DoS-4] reorder attack on {}-packet burst: {} delivered, {} dropped (window={})",
        burst, delivered, dropped, WINDOW_BITS
    );
    // Exactly the WINDOW_BITS packets before the last one are still in
    // the window (the kernel's rule: up to WINDOW_BITS behind the
    // greatest counter); the rest are dropped.
    assert_eq!(delivered, WINDOW_BITS as usize);
    assert_eq!(dropped, burst - 1 - WINDOW_BITS as usize);
}

/// THREAT MODEL 5: off-path attacker spraying transport packets at
/// guessed receiver indices. Indices are a keyed permutation of
/// (peer, slot), so a guess is right with probability (live sessions)/2³²
/// and a wrong one is rejected before any AEAD work.
#[test]
fn dos_guessed_receiver_indices_are_rejected_before_any_aead() {
    let mut p = new_pair(0xd005);
    p.establish();
    let wire = p.seal_from_a(b"reference");
    let live_index = u32::from_le_bytes(wire[4..8].try_into().unwrap());
    let mut rng = DeterministicRng::new(5);
    let now = p.clock.now();
    for _ in 0..20_000 {
        let mut guess = [0u8; 4];
        rng.fill(&mut guess).unwrap();
        if u32::from_le_bytes(guess) == live_index {
            continue;
        }
        let mut forged = vec![0u8; 64];
        forged[0] = 4;
        forged[4..8].copy_from_slice(&guess);
        assert_eq!(
            p.b.recv_from(now, x_addr(), false, &forged, &mut rng).rx,
            Rx::Dropped(DropReason::UnknownIndex)
        );
    }
    assert_eq!(p.b.tunnel.stats().auth_failures, 0, "no Poly1305 was spent");
    // Neighbouring index values are not neighbouring sessions: the indices
    // just above and below a live one are not live.
    for neighbour in [live_index.wrapping_add(1), live_index.wrapping_sub(1)] {
        let mut forged = wire.clone();
        forged[4..8].copy_from_slice(&neighbour.to_le_bytes());
        assert_eq!(
            p.deliver_to_b(&forged).rx,
            Rx::Dropped(DropReason::UnknownIndex)
        );
    }
}

/// All of a peer's state is in its `Tunnel`, all of an identity's in its
/// `Device`: nothing is allocated, so these two numbers are what a peer
/// costs. The README states them; this holds them to it, so that a field
/// that grows them shows up here and not in somebody's memory budget.
/// (The dominant part is fixed by the protocol: three sessions, each with
/// a replay window of 1024 bytes.)
#[test]
fn a_tunnel_and_a_device_fit_their_documented_budgets() {
    let tunnel = std::mem::size_of::<Tunnel>();
    let device = std::mem::size_of::<Device>();
    eprintln!("[mem] sizeof(Tunnel) = {tunnel} bytes, sizeof(Device) = {device} bytes");
    // README, "Design rules": "a `Tunnel` is 4736 bytes, a `Device`
    // 432" on a 64-bit target. To the byte: a number that is stated
    // is a number that is checked. (The tunnel's is a multiple of 64: it
    // is aligned to the cache line, see its definition.)
    #[cfg(target_pointer_width = "64")]
    {
        assert_eq!(
            tunnel, 4736,
            "a Tunnel is {tunnel} bytes: not what the README says"
        );
        assert_eq!(
            device, 432,
            "a Device is {device} bytes: not what the README says"
        );
    }
    // Whatever the target: three replay windows are in there, and the
    // whole is well under two pages.
    assert!((3 * 1024..8192).contains(&tunnel), "{tunnel}");
    assert!(device < 1024, "{device}");
}
