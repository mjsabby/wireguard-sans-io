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
use common::{Polled, Rx, S, Tx, a_addr, b_addr, id, new_pair, wall, x_addr};
use wireguard_sans_io::testing::{DeterministicRng, FailingRng};
use wireguard_sans_io::{
    Device, DropReason, Error, Incoming, PeerConfig, PublicKey, SendReason, StaticSecret, Tai64N,
    Ticks, Timer, WallClock, consts,
};

// An off-path attacker who knows the responder's public key can forge a
// HandshakeInitiation that passes mac1 AND reveals a (their own) static
// key, forcing the responder to perform ONE X25519 before the identity is
// known. This is inherent to the protocol (whitepaper §5.3); the cookie
// mechanism + caller rate-limiting is the defence. We verify the
// responder stops at the peer check (no session installed, no response
// sent) and that `under_load=true` short-circuits BEFORE the DH work.
#[test]
fn unknown_peer_forge_stops_at_peer_check() {
    let mut p = new_pair(0xa1);
    let now = p.clock.now();
    let (m_key, _) = common::keypair(&mut p.rng);
    let mut mallory = common::side(
        m_key,
        p.b.device.public_key(),
        x_addr(),
        Some(b_addr()),
        None,
        None,
        &mut p.rng,
    );
    let init = mallory.initiate(now, &mut p.rng);

    // Off-load: B does one DH, then rejects on identity.
    assert_eq!(
        p.b.recv_from(now, x_addr(), false, &init, &mut p.rng).rx,
        Rx::Dropped(DropReason::UnknownPeer)
    );
    assert_eq!(
        p.b.tunnel.stats().handshakes_responded,
        0,
        "no session installed"
    );
    assert_eq!(p.b.device.stats().initiations, 1);

    // Under load: short-circuits to a cookie reply (no Noise DH).
    match p.b.recv_from(now, x_addr(), true, &init, &mut p.rng).rx {
        Rx::CookieReply(w) => assert_eq!(w[0], 3, "cookie reply"),
        other => panic!("expected cookie reply under load, got {other:?}"),
    }
    assert_eq!(p.b.device.stats().initiations, 1, "no second DH");
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
    assert_eq!(
        p.deliver_to_b(&forged).rx,
        Rx::Dropped(DropReason::AuthFailure)
    );
    assert!(matches!(p.deliver_to_b(&wires[0]).rx, Rx::Data(_)));

    // Legitimate high-counter packet, delivered out of order: advances.
    let high = wires.pop().unwrap(); // counter = burst
    assert!(matches!(p.deliver_to_b(&high).rx, Rx::Data(_)));
    // The window now covers [burst − WINDOW_BITS, burst] (as the
    // kernel's does). A packet with a counter below that is too old; the
    // one exactly at the edge is fine — once.
    let counter_at = |wires_index: usize| wires_index + 1;
    let edge = burst - WINDOW_BITS as usize - 1;
    assert_eq!(counter_at(edge), burst - WINDOW_BITS as usize);
    let too_old = edge - 1;
    assert_eq!(
        p.deliver_to_b(&wires[too_old]).rx,
        Rx::Dropped(DropReason::Replay),
        "counter {} < {}−{} → too old",
        counter_at(too_old),
        burst,
        WINDOW_BITS
    );
    assert!(matches!(p.deliver_to_b(&wires[edge]).rx, Rx::Data(_)));
    assert_eq!(
        p.deliver_to_b(&wires[edge]).rx,
        Rx::Dropped(DropReason::Replay)
    );
    assert!(matches!(p.deliver_to_b(&wires[edge + 10]).rx, Rx::Data(_)));
}

// The greatest-timestamp record can only be moved by the configured peer:
// an initiation from any other identity never reaches it, whatever its
// timestamp says.
#[test]
fn timestamp_poisoning_requires_peer_privkey() {
    let mut p = new_pair(0xa4);
    let now = p.clock.now();
    // Mallory's device believes it is the year 2286.
    let (m_key, _) = common::keypair(&mut p.rng);
    let far_future = WallClock::new(Ticks::ZERO, 9_999_999_999, 0);
    let m_dev = Device::new(m_key, far_future, &mut p.rng).unwrap();
    let mut cfg = PeerConfig::new(p.b.device.public_key());
    cfg.endpoint = Some(b_addr());
    let mut m_tunnel = m_dev.tunnel(id(0), cfg, &mut p.rng).unwrap();
    m_tunnel.request_handshake(now);
    let mut buf = [0u8; 256];
    let m_init = match m_tunnel.poll(now, &mut buf, &mut p.rng).unwrap() {
        wireguard_sans_io::PollOutput::Transmit(tx, _) => tx.datagram.to_vec(),
        other => panic!("{other:?}"),
    };
    assert_eq!(
        p.b.recv_from(now, x_addr(), false, &m_init, &mut p.rng).rx,
        Rx::Dropped(DropReason::UnknownPeer)
    );

    // A's legitimate initiation with a normal timestamp is STILL accepted.
    let a_init = p.a_initiates();
    assert!(matches!(p.deliver_to_b(&a_init).rx, Rx::Response(_)));
}

// A captured initiation, replayed unlimited times, never mutates state
// and never elicits a response.
#[test]
fn replayed_initiation_never_mutates_state() {
    let mut p = new_pair(0xa5);
    let init = p.a_initiates();
    assert!(matches!(p.deliver_to_b(&init).rx, Rx::Response(_)));
    let stats_before = p.b.tunnel.stats();
    let timers_before: Vec<_> = Timer::ALL.iter().map(|t| p.b.tunnel.timer(*t)).collect();
    for i in 0..1000u64 {
        // …from anywhere, at any later time.
        p.clock.advance(i * 1_000_000);
        let now = p.clock.now();
        let info = p.b.recv_from(now, x_addr(), false, &init, &mut p.rng);
        assert_eq!(info.rx, Rx::Dropped(DropReason::ReplayedTimestamp));
        assert!(!info.endpoint_changed);
    }
    assert_eq!(p.b.tunnel.stats(), stats_before);
    let timers_after: Vec<_> = Timer::ALL.iter().map(|t| p.b.tunnel.timer(*t)).collect();
    assert_eq!(
        timers_after, timers_before,
        "a replay must not touch any timer"
    );
    assert_eq!(p.b.tunnel.endpoint(), Some(a_addr()));
}

// Cookie replies are sealed under a key derived from our public key alone,
// so their XChaCha20 nonces must never repeat for the life of the key.
// There is exactly one nonce counter per device — however many peers it
// has and whichever of them the challenged message claims to be from.
#[test]
fn cookie_nonces_are_unique_across_all_peers_of_a_device() {
    let mut rng = DeterministicRng::new(0xa6);
    let (server_key, server_pub) = common::keypair(&mut rng);
    let mut server = Device::new(server_key, wall(), &mut rng).unwrap();
    let now = Ticks::ZERO;

    let mut nonces = std::collections::HashSet::new();
    for i in 0..100u32 {
        // A different client identity each time.
        let (key, _) = common::keypair(&mut rng);
        let mut client = common::side(
            key,
            server_pub,
            x_addr(),
            Some(b_addr()),
            None,
            None,
            &mut rng,
        );
        let mut init = client.initiate(now, &mut rng);
        let challenge = match server.receive(now, x_addr(), true, &mut init) {
            Incoming::CookieRequired(c) => c,
            other => panic!("{other:?}"),
        };
        let mut out = [0u8; 64];
        let reply = server
            .cookie_reply(now, &challenge, &mut out, &mut rng)
            .unwrap();
        let nonce: [u8; 24] = reply.datagram[8..32].try_into().unwrap();
        assert!(
            nonces.insert(nonce),
            "XChaCha20 nonce {nonce:02x?} REUSED at reply {i} — Poly1305 one-time-key reuse"
        );
    }
    assert_eq!(nonces.len(), 100);
}

// Documents a caller-misuse hazard that remains: two *devices* created
// with the same static key and fed the SAME entropy stream (a cloned VM, a
// broken RNG) seed their cookie nonce counters identically and collide
// under the shared cookie key. Independent entropy is all it takes to
// avoid it.
#[test]
fn identical_entropy_across_devices_sharing_a_key_collides_cookie_nonces() {
    let mut rng = DeterministicRng::new(0xa7);
    let (server_key, server_pub) = common::keypair(&mut rng);
    let (client_key, _) = common::keypair(&mut rng);
    let mut client = common::side(
        client_key,
        server_pub,
        x_addr(),
        Some(b_addr()),
        None,
        None,
        &mut rng,
    );
    let now = Ticks::ZERO;
    let init = client.initiate(now, &mut rng);

    let nonce_from = |seed: u64| {
        let mut r = DeterministicRng::new(seed);
        let mut dev = Device::new(server_key.clone(), wall(), &mut r).unwrap();
        let mut copy = init.clone();
        let Incoming::CookieRequired(challenge) = dev.receive(now, x_addr(), true, &mut copy)
        else {
            panic!("expected a cookie challenge");
        };
        let mut out = [0u8; 64];
        dev.cookie_reply(now, &challenge, &mut out, &mut r)
            .unwrap()
            .datagram[8..32]
            .to_vec()
    };
    assert_eq!(
        nonce_from(0xdead),
        nonce_from(0xdead),
        "identical entropy ⇒ identical nonces under a SHARED key"
    );
    assert_ne!(
        nonce_from(0xdead),
        nonce_from(0xbeef),
        "independent entropy is safe"
    );
}

// Nothing is written to the output buffer on any path that does not
// produce a datagram.
#[test]
fn output_buffer_untouched_on_every_non_sending_path() {
    let mut p = new_pair(0xa8);
    let now = p.clock.now();
    let init = p.a_initiates();
    assert!(matches!(p.deliver_to_b(&init).rx, Rx::Response(_)));

    // Replay → dropped, nothing written.
    let mut out = [0xEEu8; 256];
    let mut copy = init.clone();
    let handled =
        p.b.device
            .receive_for(
                &mut p.b.tunnel,
                now,
                a_addr(),
                false,
                &mut copy,
                &mut out,
                &mut p.rng,
            )
            .unwrap();
    assert!(matches!(
        handled.received,
        wireguard_sans_io::Received::Dropped(DropReason::ReplayedTimestamp)
    ));
    assert!(
        out.iter().all(|&b| b == 0xEE),
        "ReplayedTimestamp dirtied out"
    );

    // Entropy failure while building the response → local fault, nothing
    // written, and nothing consumed.
    let later = p.clock.advance(6 * S);
    let init2 = p.a.initiate(later, &mut p.rng);
    let mut out = [0xEEu8; 256];
    let mut copy = init2.clone();
    let r = p.b.device.receive_for(
        &mut p.b.tunnel,
        later,
        a_addr(),
        false,
        &mut copy,
        &mut out,
        &mut FailingRng,
    );
    assert!(matches!(r, Err(Error::EntropyFailure)));
    assert!(out.iter().all(|&b| b == 0xEE), "EntropyFailure dirtied out");
    assert_eq!(p.b.tunnel.stats().handshakes_responded, 1);
    // The same initiation is accepted once entropy works again: its
    // timestamp was not recorded by the failed attempt.
    assert!(matches!(p.deliver_to_b(&init2).rx, Rx::Response(_)));
}

// A legitimate peer churning the responder's `next` slot never disturbs
// `current`/`previous`.
#[test]
fn next_slot_churn_does_not_affect_current() {
    let mut p = new_pair(0xa9);
    p.establish();
    p.assert_roundtrip_a_to_b(b"baseline");
    let completed_before = p.b.tunnel.stats().handshakes_completed;

    for i in 0..50u64 {
        p.clock.advance(6 * S);
        let init = p.a_initiates();
        match p.deliver_to_b(&init).rx {
            Rx::Response(_) => {}
            other => panic!("init #{i}: {other:?}"),
        }
        if p.clock.mono_ns < consts::REJECT_AFTER_TIME {
            p.assert_roundtrip_a_to_b(b"during churn");
        }
    }
    assert_eq!(p.b.tunnel.stats().handshakes_completed, completed_before);
    assert_eq!(p.b.tunnel.stats().handshakes_responded, 51);
}

// Exhaustive single-bit confidentiality lock on transport data: no
// forgery ever causes a single byte to be decrypted.
#[test]
fn no_plaintext_on_any_single_bit_forgery() {
    let mut p = new_pair(0xa11);
    p.establish();
    let secret = b"FLIGHT-CRITICAL TELEMETRY: ALT=35000 HDG=270 IAS=450";
    let wire = p.seal_from_a(secret);
    let now = p.clock.now();
    for byte in 0..wire.len() {
        for bit in 0..8 {
            let mut bad = wire.clone();
            bad[byte] ^= 1 << bit;
            let (info, after) = p.b.recv_in_place(now, a_addr(), &bad, &mut p.rng);
            assert!(
                matches!(info.rx, Rx::Dropped(_)),
                "byte {byte} bit {bit} accepted"
            );
            assert_eq!(
                after, bad,
                "CONFIDENTIALITY VIOLATION at byte {byte} bit {bit}: buffer was modified"
            );
        }
    }
    // The genuine datagram decrypts, in place.
    let (info, after) = p.b.recv_in_place(now, a_addr(), &wire, &mut p.rng);
    assert!(matches!(info.rx, Rx::Data(_)));
    assert_eq!(&after[16..16 + secret.len()], secret);
}

// Debug formatting of every secret-bearing type leaks nothing.
#[test]
fn debug_never_leaks_secrets() {
    let mut rng = DeterministicRng::new(0xa12);
    // Distinctive secret bytes we can grep for.
    let sk = StaticSecret::from_bytes([0xA7u8; 32]);
    let psk = wireguard_sans_io::PresharedKey::from_bytes([0xB9u8; 32]);
    let device = Device::new(sk.clone(), wall(), &mut rng).unwrap();
    let mut cfg = PeerConfig::new(PublicKey::from_bytes([7; 32]));
    cfg.psk = psk.clone();
    cfg.endpoint = Some(b_addr());
    let mut tunnel = device.tunnel(id(1), cfg, &mut rng).unwrap();
    tunnel.request_handshake(Ticks::ZERO);
    let mut buf = [0u8; 256];
    let _ = tunnel.poll(Ticks::ZERO, &mut buf, &mut rng).unwrap();

    let dump = format!(
        "{sk:?} {psk:?} {device:?} {tunnel:?} {:?} {:?} {:?}",
        tunnel.stats(),
        device.stats(),
        tunnel.next_wake()
    );
    for needle in [
        "a7a7a7a7", "b9b9b9b9", "A7A7A7A7", "B9B9B9B9", "167, 167", "185, 185",
    ] {
        assert!(
            !dump.contains(needle),
            "Debug output leaks secret-distinctive bytes: {needle:?} in {dump:?}"
        );
    }
    assert!(dump.contains("StaticSecret(REDACTED)"));
    assert!(dump.contains("PresharedKey(REDACTED)"));
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
        let _ = p.a.drain(now, &mut p.rng);
        let _ = p.b.drain(now, &mut p.rng);
        if let Tx::Transport(w) = p.a.send(now, b"data") {
            captured.push(w);
        }
        // Replay everything ever captured, from everywhere.
        for w in &captured {
            let _ = p.b.recv_from(now, x_addr(), false, w, &mut p.rng);
        }
        let mut g = vec![round as u8; 148];
        g[0] = 1;
        let _ = p.b.recv_from(now, x_addr(), false, &g, &mut p.rng);
    }

    p.clock.advance(600 * S);
    let mut connected = false;
    for _ in 0..200 {
        p.clock.advance(S);
        let now = p.clock.now();
        // A faithful network: everything either side emits is delivered.
        let mut wires: Vec<(bool, Vec<u8>)> = vec![];
        for (w, _) in p.a.drain(now, &mut p.rng).0 {
            wires.push((true, w));
        }
        for (w, _) in p.b.drain(now, &mut p.rng).0 {
            wires.push((false, w));
        }
        if let Tx::Transport(w) = p.a.send(now, b"probe") {
            wires.push((true, w));
        }
        while let Some((to_b, w)) = wires.pop() {
            let info = if to_b {
                p.deliver_to_b(&w)
            } else {
                p.deliver_to_a(&w)
            };
            match info.rx {
                Rx::Response(r) => wires.push((!to_b, r)),
                Rx::Data(d) if to_b && d.starts_with(b"probe") => connected = true,
                _ => {}
            }
        }
        if connected {
            break;
        }
    }
    assert!(connected, "tunnel failed to recover after maximal abuse");
}

// The busy-loop property: an Idle poll result never coexists with a
// next_wake that is not in the future — here with a persistent keepalive
// and a peer that has gone silent, for ten minutes.
#[test]
fn idle_never_coexists_with_a_due_wake_up() {
    let mut p = common::new_pair_with(0xa14, None, Some(25));
    p.establish();
    p.clock.advance(119 * S);
    let _ = p.seal_from_a(b"x");
    let mut polls = 0;
    while p.clock.mono_ns <= 600 * S {
        let Some(wake) = p.a.tunnel.next_wake() else {
            break;
        };
        let now = p.clock.set(wake);
        // `drain` asserts next_wake is strictly in the future once Idle.
        let _ = p.a.drain(now, &mut p.rng);
        polls += 1;
        assert!(polls < 1000, "spinning: {polls} wake-ups in 600 s");
    }
    assert!(
        p.a.tunnel.stats().handshakes_initiated > 1,
        "it did keep trying"
    );
}

// ---------------------------------------------------------------------------
// Endpoint (roaming) rules: the peer's endpoint moves on authenticated
// messages and on nothing else.
// ---------------------------------------------------------------------------

#[test]
fn unauthenticated_datagrams_never_move_the_endpoint() {
    let mut p = new_pair(0xa15);
    p.establish();
    p.assert_roundtrip_a_to_b(b"baseline");
    let now = p.clock.advance(6 * S);
    let outsider = x_addr();

    // What an attacker can send without any key, plus everything a
    // recorded exchange gives them to replay.
    let genuine_data = p.seal_from_a(b"captured");
    assert!(matches!(p.deliver_to_b(&genuine_data).rx, Rx::Data(_)));
    let genuine_init = p.a.initiate(now, &mut p.rng);
    assert!(matches!(p.deliver_to_b(&genuine_init).rx, Rx::Response(_)));
    let (m_key, _) = common::keypair(&mut p.rng);
    let mut mallory = common::side(
        m_key,
        p.b.device.public_key(),
        outsider,
        Some(b_addr()),
        None,
        None,
        &mut p.rng,
    );
    let mallory_init = mallory.initiate(now, &mut p.rng);
    let mut forged_data = genuine_data.clone();
    forged_data[8..16].copy_from_slice(&999u64.to_le_bytes());

    let attempts: Vec<(&str, Vec<u8>, bool)> = vec![
        ("replayed transport", genuine_data.clone(), false),
        ("replayed initiation", genuine_init.clone(), false),
        ("forged transport", forged_data, false),
        (
            "initiation from an unknown identity",
            mallory_init.clone(),
            false,
        ),
        ("initiation under load (cookie reply)", mallory_init, true),
        ("replayed initiation under load", genuine_init, true),
        ("garbage", vec![0xab; 80], false),
    ];
    for (what, datagram, under_load) in attempts {
        let info =
            p.b.recv_from(now, outsider, under_load, &datagram, &mut p.rng);
        assert!(
            matches!(info.rx, Rx::Dropped(_) | Rx::CookieReply(_)),
            "{what}: {:?}",
            info.rx
        );
        assert!(!info.endpoint_changed, "{what}");
        assert_eq!(
            p.b.tunnel.endpoint(),
            Some(a_addr()),
            "{what} moved the endpoint"
        );
    }

    // B's own traffic still goes to A.
    let now = p.clock.now();
    assert_eq!(
        p.b.tunnel
            .encapsulate(now, b"to a", &mut [0u8; 64])
            .map(|e| match e {
                wireguard_sans_io::Encapsulated::Transport(tx) => Some(tx.dst),
                _ => None,
            }),
        Ok(Some(a_addr()))
    );
}

/// The endpoint is where the peer has last *proved to be*: it moves with
/// every message that only the live peer can have sent from there — a
/// response to our initiation, and transport data. A handshake initiation
/// is answered where it came from, but does not move an endpoint that is
/// known: it may be a recording (see the next test).
#[test]
fn the_endpoint_follows_what_only_the_live_peer_can_send() {
    let roam = |n: u16| -> std::net::SocketAddr {
        format!("198.51.100.{n}:{}", 1000 + n).parse().unwrap()
    };
    let mut p = new_pair(0xa16);

    // Initiation, from somewhere new: the response goes there; the
    // endpoint B was configured with stays.
    let now = p.clock.now();
    let init = p.a_initiates();
    let info = p.b.recv_from(now, roam(1), false, &init, &mut p.rng);
    let resp = match info.rx {
        Rx::Response(w) => w,
        other => panic!("{other:?}"),
    };
    assert_eq!(info.reply_dst, Some(roam(1)));
    assert!(!info.endpoint_changed);
    assert_eq!(p.b.tunnel.endpoint(), Some(a_addr()));

    // Response: it answers the initiation we have just made, so whoever
    // sent it is the peer, now.
    let info = p.a.recv_from(now, roam(2), false, &resp, &mut p.rng);
    assert_eq!(info.rx, Rx::HandshakeComplete);
    assert!(info.endpoint_changed);
    assert_eq!(p.a.tunnel.endpoint(), Some(roam(2)));

    // Keepalive (the confirmation): the peer uses the session, and B's
    // endpoint moves to where it does so from.
    let ka = match p.a.poll(now, &mut p.rng) {
        Polled::Transmit(w, SendReason::Keepalive, dst) => {
            assert_eq!(dst, roam(2), "sent to where the response came from");
            w
        }
        other => panic!("{other:?}"),
    };
    let info = p.b.recv_from(now, roam(3), false, &ka, &mut p.rng);
    assert_eq!(info.rx, Rx::Keepalive);
    assert!(info.endpoint_changed);
    assert_eq!(p.b.tunnel.endpoint(), Some(roam(3)));

    // Data.
    let data = p.seal_from_a(b"hello");
    let info = p.b.recv_from(now, roam(4), false, &data, &mut p.rng);
    assert!(matches!(info.rx, Rx::Data(_)));
    assert!(info.endpoint_changed);
    assert_eq!(p.b.tunnel.endpoint(), Some(roam(4)));

    // Same address again: nothing changed.
    let data = p.seal_from_a(b"again");
    let info = p.b.recv_from(now, roam(4), false, &data, &mut p.rng);
    assert!(!info.endpoint_changed);

    // set_endpoint is the embedder's override; a later authenticated
    // message still wins.
    p.b.tunnel.set_endpoint(a_addr());
    assert_eq!(p.b.tunnel.endpoint(), Some(a_addr()));
    let data = p.seal_from_a(b"roamed");
    assert!(
        p.b.recv_from(now, roam(5), false, &data, &mut p.rng)
            .endpoint_changed
    );
    assert_eq!(p.b.tunnel.endpoint(), Some(roam(5)));

    // A rekey from yet another address. By now the peer has used a
    // session that an initiation of its own created (the keepalive
    // above), which no recording could: its timestamps are tied to real
    // time, a later one was made later, and the endpoint follows the
    // initiation at once — as it does, always, for the Linux
    // implementation. What B sends next goes there, on the session it
    // already has.
    let later = p.clock.advance(6 * S);
    let init = p.a_initiates();
    let info = p.b.recv_from(later, roam(6), false, &init, &mut p.rng);
    assert_eq!(info.reply_dst, Some(roam(6)));
    assert!(info.endpoint_changed);
    assert_eq!(p.b.tunnel.endpoint(), Some(roam(6)));
    assert_eq!(data_destination(&mut p.b, later), Some(roam(6)));
    let Rx::Response(resp) = info.rx else {
        panic!("{:?}", info.rx)
    };
    assert_eq!(p.deliver_to_a(&resp).rx, Rx::HandshakeComplete);
    let data = p.seal_from_a(b"on the new session");
    let info = p.b.recv_from(later, roam(6), false, &data, &mut p.rng);
    assert!(info.session_established && !info.endpoint_changed);
    assert_eq!(p.b.tunnel.endpoint(), Some(roam(6)));
}

/// `count` initiations of A's, made `gap` apart — what someone on the
/// path can record over time. Their timestamps increase, so a tunnel that
/// has seen none of them accepts each in turn.
fn recordings(seed: u64, count: usize, gap: u64) -> Vec<Vec<u8>> {
    let mut p = new_pair(seed);
    (0..count)
        .map(|_| {
            p.clock.advance(gap);
            p.a_initiates()
        })
        .collect()
}

/// Where a side's next data message goes, if it has a session to send
/// it on.
fn data_destination(side: &mut common::Side, now: Ticks) -> Option<std::net::SocketAddr> {
    let mut wire = [0u8; 256];
    match side.tunnel.encapsulate(now, b"data", &mut wire).unwrap() {
        wireguard_sans_io::Encapsulated::Transport(tx) => Some(tx.dst),
        _ => None,
    }
}

/// A side's next handshake initiation, when it is sent and where it
/// goes: polled at every wake-up until one comes out.
fn next_initiation(
    side: &mut common::Side,
    rng: &mut DeterministicRng,
) -> (Ticks, Vec<u8>, std::net::SocketAddr) {
    loop {
        let at = side.tunnel.next_wake().expect("an initiation is scheduled");
        match side.poll(at, rng) {
            Polled::Transmit(
                wire,
                SendReason::HandshakeInitiation | SendReason::HandshakeRetransmit,
                dst,
            ) => return (at, wire, dst),
            // Nothing to send at this wake-up, or a keepalive.
            Polled::Idle | Polled::Transmit(..) => {}
            other => panic!("{other:?}"),
        }
    }
}

/// A tunnel that has just been created has no record of the peer's
/// timestamps (after a restart, or when it was re-created to get rid of a
/// poisoned one), so it cannot tell a recording of an old initiation from
/// a new one, and answers it. That must be all it does for it: the
/// endpoint stays, what the tunnel sends on its sessions goes to the
/// peer, and of its own handshake initiations — which do try the address
/// the recording came from, because a peer that has really moved is
/// found no other way — every other one goes to the peer. The handshake
/// with the peer is one Rekey-Timeout late, and that is the damage.
#[test]
fn a_replayed_initiation_cannot_redirect_a_new_tunnel() {
    let mut p = new_pair(0xa17);
    // Yesterday: a handshake the attacker recorded.
    let recorded = p.a_initiates();
    let now = p.clock.now();
    assert!(matches!(p.deliver_to_b(&recorded).rx, Rx::Response(_)));

    // Today B restarts: same keys, same configuration, a new tunnel.
    let mut p2 = new_pair(0xa17);
    assert_eq!(p2.b.tunnel.endpoint(), Some(a_addr()));
    let attacker = common::x_addr();
    let later = now.add_nanos(3600 * S);
    p2.clock.set(later);
    let info =
        p2.b.recv_from(later, attacker, false, &recorded, &mut p2.rng);
    // Answered (92 bytes, to the sender: no amplification), and the
    // endpoint is where it was.
    assert!(matches!(info.rx, Rx::Response(_)), "{:?}", info.rx);
    assert_eq!(info.reply_dst, Some(attacker));
    assert!(!info.endpoint_changed);
    assert_eq!(p2.b.tunnel.endpoint(), Some(a_addr()));

    // B's own handshake: the first initiation tries the address the
    // recording came from, the second goes to the peer…
    p2.b.tunnel.request_handshake(later);
    let (_, _, first) = next_initiation(&mut p2.b, &mut p2.rng);
    assert_eq!(first, attacker);
    assert_eq!(
        p2.b.tunnel.endpoint(),
        Some(a_addr()),
        "trying is not believing"
    );
    let (at, init, second) = next_initiation(&mut p2.b, &mut p2.rng);
    assert_eq!(second, a_addr());
    assert!(at.since(later) <= 2 * consts::REKEY_TIMEOUT + consts::REKEY_TIMEOUT_JITTER_MAX);
    // …who answers, and that settles it.
    let Rx::Response(resp) = p2.a.recv_from(at, b_addr(), false, &init, &mut p2.rng).rx else {
        panic!("A answers")
    };
    let info = p2.b.recv_from(at, a_addr(), false, &resp, &mut p2.rng);
    assert_eq!(info.rx, Rx::HandshakeComplete);
    assert!(!info.endpoint_changed);
    assert_eq!(p2.b.tunnel.endpoint(), Some(a_addr()));
    assert_eq!(data_destination(&mut p2.b, at), Some(a_addr()));
    // The candidate is forgotten: the next handshake starts with the peer.
    let much_later = at.add_nanos(200 * S);
    p2.b.tunnel.request_handshake(much_later);
    let (_, _, dst) = next_initiation(&mut p2.b, &mut p2.rng);
    assert_eq!(dst, a_addr());

    // The same recording again is refused: its timestamp is on record now.
    assert_eq!(
        p2.b.recv_from(much_later, attacker, false, &recorded, &mut p2.rng)
            .rx,
        Rx::Dropped(DropReason::ReplayedTimestamp)
    );
}

/// The reason our own initiations try the address an unproven initiation
/// came from. The peer has moved; the endpoint we were configured with is
/// stale. The peer starts a handshake from where it is now, we answer
/// there — and the packet with which the peer would confirm the session
/// is lost, and the peer has nothing else to send. Without the candidate
/// address we would go on initiating to the stale endpoint for as long as
/// we had something to send, and never reach the peer (the Linux
/// implementation moves its endpoint on the initiation and reaches it with
/// its next message).
#[test]
fn a_peer_that_moved_is_found_by_our_own_initiation() {
    let mut p = new_pair(0xa19);
    let now = p.clock.now();
    let moved: std::net::SocketAddr = "203.0.113.9:40000".parse().unwrap();
    let init = p.a_initiates();
    let info = p.b.recv_from(now, moved, false, &init, &mut p.rng);
    let Rx::Response(resp) = info.rx else {
        panic!("{:?}", info.rx)
    };
    assert_eq!(info.reply_dst, Some(moved));
    assert_eq!(p.b.tunnel.endpoint(), Some(a_addr()), "the stale endpoint");
    assert_eq!(p.deliver_to_a(&resp).rx, Rx::HandshakeComplete);
    let (_lost_confirmation, _) = p.a.drain(now, &mut p.rng);

    // B has data for A and no session it may send on yet.
    assert!(matches!(p.b.send(now, b"for the peer"), Tx::NoSession));
    let (at, init, dst) = next_initiation(&mut p.b, &mut p.rng);
    assert_eq!(
        dst, moved,
        "the first initiation goes where the peer was heard from"
    );
    assert_eq!(
        at.since(now),
        consts::REKEY_TIMEOUT,
        "as soon as the pacing allows"
    );
    // A is there, answers, and now B knows.
    let Rx::Response(resp) = p.a.recv_from(at, b_addr(), false, &init, &mut p.rng).rx else {
        panic!("A answers")
    };
    let info = p.b.recv_from(at, moved, false, &resp, &mut p.rng);
    assert_eq!(info.rx, Rx::HandshakeComplete);
    assert!(info.endpoint_changed);
    assert_eq!(p.b.tunnel.endpoint(), Some(moved));
    assert_eq!(data_destination(&mut p.b, at), Some(moved));
}

/// However many recordings someone has, and however they time them, at
/// least every other initiation of ours goes to the endpoint: a new
/// candidate does not put itself at the front of the queue.
#[test]
fn recordings_replayed_before_each_of_our_initiations_get_every_other_one_at_most() {
    let recorded = recordings(0xa20, 12, 7 * S);
    let mut p = new_pair(0xa20);
    let start = Ticks::from_secs(100_000);
    p.clock.set(start);
    p.b.tunnel.request_handshake(start);
    let mut destinations = Vec::new();
    let mut at = start;
    for (n, recording) in recorded.iter().enumerate() {
        // A different address every time, just before our initiation is
        // due.
        let attacker: std::net::SocketAddr = format!("198.51.100.{}:9", 10 + n).parse().unwrap();
        let info = p.b.recv_from(at, attacker, false, recording, &mut p.rng);
        assert!(matches!(info.rx, Rx::Response(_)), "{n}: {:?}", info.rx);
        assert_eq!(p.b.tunnel.endpoint(), Some(a_addr()));
        let (sent_at, _, dst) = next_initiation(&mut p.b, &mut p.rng);
        destinations.push(dst);
        at = sent_at.add_nanos(4 * S);
    }
    let to_peer = destinations.iter().filter(|d| **d == a_addr()).count();
    assert!(to_peer >= destinations.len() / 2, "{destinations:?}");
    for pair in destinations.windows(2) {
        assert!(
            pair[0] == a_addr() || pair[1] == a_addr(),
            "two initiations in a row went elsewhere: {destinations:?}"
        );
    }
    // And when the attempt is given up, the candidate goes with it.
    let mut gave_up = false;
    while let Some(wake) = p.b.tunnel.next_wake() {
        match p.b.poll(wake, &mut p.rng) {
            Polled::HandshakeExpired => {
                gave_up = true;
                break;
            }
            Polled::Transmit(..) | Polled::Idle => {}
            other => panic!("{other:?}"),
        }
    }
    assert!(gave_up);
    let again = p.b.tunnel.next_wake().unwrap_or(at).add_nanos(100 * S);
    p.b.tunnel.request_handshake(again);
    let (_, _, dst) = next_initiation(&mut p.b, &mut p.rng);
    assert_eq!(dst, a_addr());
}

/// Answering an initiation holds back a handshake of our own for
/// Rekey-Timeout (the peer's is about to complete, and two that cross are
/// one too many), as in the Linux implementation. There, every further
/// response holds it back again; a new tunnel answers every recording it
/// is sent, so forty of them, replayed a little under five seconds apart,
/// used to keep it from starting a handshake for more than three minutes.
/// Responses that nothing confirms hold an initiation back for three
/// Rekey-Timeouts from the first of them, and no longer.
#[test]
fn replayed_recordings_hold_back_our_own_handshake_for_a_bounded_time() {
    let recorded = recordings(0xa21, 40, 6 * S);
    let mut p = new_pair(0xa21);
    let start = Ticks::from_secs(100_000);
    p.clock.set(start);
    let mut first_initiation = None;
    for (n, recording) in recorded.iter().enumerate() {
        let at = start.add_nanos(n as u64 * 4_900_000_000);
        // Everything that is due before the next replay arrives.
        while let Some(wake) = p.b.tunnel.next_wake().filter(|w| *w < at) {
            if let Polled::Transmit(_, SendReason::HandshakeInitiation, _) =
                p.b.poll(wake, &mut p.rng)
            {
                first_initiation.get_or_insert(wake);
            }
        }
        let info = p.b.recv_from(at, x_addr(), false, recording, &mut p.rng);
        assert!(matches!(info.rx, Rx::Response(_)), "{n}: {:?}", info.rx);
        if n == 0 {
            // From the first replay on, B has something to send.
            assert!(matches!(p.b.send(start, b"waiting"), Tx::NoSession));
        }
    }
    let first_initiation = first_initiation.expect("B never started its handshake");
    assert_eq!(
        first_initiation.since(start),
        consts::UNCONFIRMED_RESPONSE_HOLD,
        "held back from the first response, for the bound and no longer"
    );
}

/// The hold itself, where it belongs: one response, and a handshake of
/// our own waits Rekey-Timeout for the peer's to complete — which it
/// does, and then ours is not needed at all.
#[test]
fn a_response_holds_our_own_initiation_back_for_rekey_timeout() {
    let mut p = new_pair(0xa22);
    let now = p.clock.now();
    let init = p.a_initiates();
    let Rx::Response(resp) = p.deliver_to_b(&init).rx else {
        panic!("B answers")
    };
    // B wants to send, and may not initiate yet.
    assert!(matches!(p.b.send(now, b"waiting"), Tx::NoSession));
    assert_eq!(
        p.b.tunnel.timer(Timer::SendInitiation),
        Some(now.add_nanos(consts::REKEY_TIMEOUT))
    );
    assert_eq!(
        p.b.poll(now.add_nanos(consts::REKEY_TIMEOUT - 1), &mut p.rng),
        Polled::Idle
    );
    // The peer's handshake completes in the meantime; B's is dropped.
    assert_eq!(p.deliver_to_a(&resp).rx, Rx::HandshakeComplete);
    let (wires, _) = p.a.drain(now, &mut p.rng);
    let info = p.b.recv_from(now, a_addr(), false, &wires[0].0, &mut p.rng);
    assert!(info.session_established);
    assert!(matches!(
        p.b.send(now, b"no longer waiting"),
        Tx::Transport(..)
    ));
    assert_eq!(p.b.tunnel.timer(Timer::SendInitiation), None);
}

/// The bound on the hold counts from the first response that nothing has
/// confirmed. Once something has — the peer used the session, or a
/// handshake of our own completed — the next response starts a new count:
/// a peer that rekeys every two minutes holds our initiation back for
/// Rekey-Timeout every time, not just the first.
#[test]
fn the_hold_starts_afresh_once_a_handshake_has_completed() {
    let mut p = new_pair(0xa23);
    // Does a response at `now` hold B's own initiation until
    // `now + Rekey-Timeout`?
    fn held(p: &mut common::Pair) -> bool {
        let now = p.clock.now();
        let init = p.a_initiates();
        assert!(matches!(p.deliver_to_b(&init).rx, Rx::Response(_)));
        p.b.tunnel.request_handshake(now);
        let due = p.b.tunnel.timer(Timer::SendInitiation);
        assert!(due.is_some());
        due == Some(now.add_nanos(consts::REKEY_TIMEOUT))
    }

    // 1. A's handshake, confirmed by A's keepalive.
    let now = p.clock.now();
    let init = p.a_initiates();
    let Rx::Response(resp) = p.deliver_to_b(&init).rx else {
        panic!("B answers")
    };
    assert_eq!(p.deliver_to_a(&resp).rx, Rx::HandshakeComplete);
    let (wires, _) = p.a.drain(now, &mut p.rng);
    assert!(p.deliver_to_b(&wires[0].0).session_established);
    // Twenty seconds later A starts another one (which B answers and A
    // never completes): held, although the first response of all is only
    // twenty seconds old.
    p.clock.advance(20 * S);
    assert!(held(&mut p), "after the peer confirmed a session");

    // 2. That response stays unconfirmed. B's own handshake goes out when
    // the hold is over, and completes.
    let (at, init, _) = next_initiation(&mut p.b, &mut p.rng);
    p.clock.set(at);
    let Rx::Response(resp) = p.deliver_to_a(&init).rx else {
        panic!("A answers")
    };
    assert_eq!(p.deliver_to_b(&resp).rx, Rx::HandshakeComplete);
    // Twenty seconds later A starts yet another: held again, for
    // Rekey-Timeout — the unconfirmed response from before B's own
    // handshake no longer counts.
    p.clock.advance(20 * S);
    assert!(held(&mut p), "after a handshake of our own completed");

    // 3. Without anything in between it does not start afresh. B's
    // handshake completes once more (so that B is not in the middle of an
    // attempt); A sends an initiation that B answers and nothing
    // confirms; twenty seconds on, another. The count from the first of
    // the two is over, and the second holds nothing back.
    let (at, init, _) = next_initiation(&mut p.b, &mut p.rng);
    p.clock.set(at);
    let Rx::Response(resp) = p.deliver_to_a(&init).rx else {
        panic!("A answers")
    };
    assert_eq!(p.deliver_to_b(&resp).rx, Rx::HandshakeComplete);
    p.clock.advance(20 * S);
    let unconfirmed = p.a_initiates();
    assert!(matches!(p.deliver_to_b(&unconfirmed).rx, Rx::Response(_)));
    p.clock.advance(20 * S);
    assert!(!held(&mut p), "nothing confirmed the response before");
}

/// A tunnel that knows no endpoint has none to protect: the source of the
/// first initiation it answers is its first guess (so that it can reach
/// the peer at all should it need to), and the guess is corrected like any
/// other endpoint — by what only the live peer can send.
#[test]
fn a_tunnel_without_an_endpoint_takes_the_first_initiations_source() {
    let mut p = common::new_pair_opts(
        0xa18,
        common::Opts {
            b_without_endpoint: true,
            ..common::Opts::default()
        },
    );
    let now = p.clock.now();
    assert_eq!(p.b.tunnel.endpoint(), None);
    let elsewhere: std::net::SocketAddr = "198.51.100.77:7777".parse().unwrap();
    let init = p.a_initiates();
    let info = p.b.recv_from(now, elsewhere, false, &init, &mut p.rng);
    let Rx::Response(resp) = info.rx else {
        panic!("{:?}", info.rx)
    };
    assert!(info.endpoint_changed);
    assert_eq!(p.b.tunnel.endpoint(), Some(elsewhere));
    // The peer turns out to be at its usual address.
    assert_eq!(p.deliver_to_a(&resp).rx, Rx::HandshakeComplete);
    let (wires, _) = p.a.drain(now, &mut p.rng);
    let info = p.b.recv_from(now, a_addr(), false, &wires[0].0, &mut p.rng);
    assert!(info.session_established && info.endpoint_changed);
    assert_eq!(p.b.tunnel.endpoint(), Some(a_addr()));
}
