//! Crafted-input rejection tests: every datagram an attacker could craft
//! must be rejected without panicking, without leaving plaintext in any
//! buffer, and without corrupting tunnel state.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unreachable
)]

mod common;
use common::{Rx, RxInfo, Side, a_addr, b_addr, new_pair, x_addr};
use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{DropReason, EntropySource, Incoming, Ticks};

/// Feed a hostile datagram; whatever happens it must be dropped, the
/// datagram buffer (where transport data would be decrypted in place) must
/// be byte-for-byte unchanged, and the output buffer must not receive any
/// bytes.
fn must_reject(side: &mut Side, now: Ticks, datagram: &[u8], what: &str) -> DropReason {
    let mut rng = DeterministicRng::new(0x6666);
    let mut copy = datagram.to_vec();
    let mut out = [0xEEu8; 256];
    let info = {
        let handled = side
            .device
            .receive_for(
                &mut side.tunnel,
                now,
                x_addr(),
                false,
                &mut copy,
                &mut out,
                &mut rng,
            )
            .unwrap_or_else(|e| panic!("{what}: local fault {e:?} from hostile input"));
        RxInfo::from_handled(&handled)
    };
    let Rx::Dropped(reason) = info.rx else {
        panic!("{what}: accepted {:?}", info.rx);
    };
    assert!(
        !info.session_established && !info.endpoint_changed,
        "{what}"
    );
    assert_eq!(
        copy, datagram,
        "{what}: datagram buffer was modified on failure"
    );
    assert!(
        out.iter().all(|&b| b == 0xEE),
        "{what}: output buffer was written on failure"
    );
    reason
}

#[test]
fn bit_flip_storm_on_every_message_type() {
    let mut p = new_pair(60);
    let now = p.clock.now();

    // Collect one pristine instance of each handshake message.
    let init = p.a_initiates();
    let resp = match p.deliver_to_b(&init).rx {
        Rx::Response(w) => w,
        other => panic!("{other:?}"),
    };

    // Every single-bit corruption of the initiation against the
    // responder: all rejected. mac1 covers everything before the macs;
    // mac2 is not covered by mac1 and is ignored off-load, so a flip
    // confined there leaves a valid message — which must then be rejected
    // as a timestamp replay (it was already consumed).
    for byte in 0..init.len() {
        for bit in [0u8, 3, 7] {
            let mut bad = init.clone();
            bad[byte] ^= 1 << bit;
            let reason = must_reject(&mut p.b, now, &bad, &format!("init byte {byte} bit {bit}"));
            let expected = match byte {
                0..=3 => DropReason::Malformed,
                4..=131 => DropReason::InvalidMac1,
                _ => DropReason::ReplayedTimestamp,
            };
            assert_eq!(reason, expected, "init byte {byte} bit {bit}");
        }
    }

    // Same for the response against the initiator — excluding the mac2
    // field: when not under load, mac2 is *ignored by design* (whitepaper
    // §5.4.4), so a flip confined there yields a message that correctly
    // completes the handshake. Everything covered by mac1 must reject.
    for byte in 0..resp.len() - 16 {
        for bit in [0u8, 4] {
            let mut bad = resp.clone();
            bad[byte] ^= 1 << bit;
            must_reject(&mut p.a, now, &bad, &format!("resp byte {byte} bit {bit}"));
        }
    }

    // The pristine response still completes the handshake: the storm did
    // not corrupt the in-flight state.
    assert_eq!(p.deliver_to_a(&resp).rx, Rx::HandshakeComplete);
    // The storm came from an outsider's address: no endpoint moved.
    assert_eq!(p.a.tunnel.endpoint(), Some(b_addr()));
    assert_eq!(p.b.tunnel.endpoint(), Some(a_addr()));
}

#[test]
fn bit_flip_storm_on_transport_data() {
    let mut p = new_pair(61);
    p.establish();
    let wire = p.seal_from_a(b"super secret payload!");
    let now = p.clock.now();
    for byte in 0..wire.len() {
        for bit in [0u8, 7] {
            let mut bad = wire.clone();
            bad[byte] ^= 1 << bit;
            must_reject(&mut p.b, now, &bad, &format!("byte {byte} bit {bit}"));
        }
    }
    // Pristine datagram still decrypts: state survived ~800 forgeries.
    let got = p.open_at_b(&wire);
    assert_eq!(&got[..21], b"super secret payload!");
    assert_eq!(
        p.b.tunnel.endpoint(),
        Some(a_addr()),
        "forgeries do not roam"
    );
}

#[test]
fn truncation_and_extension_sweeps() {
    let mut p = new_pair(62);
    p.establish();
    let now = p.clock.now();
    let transport = p.seal_from_a(b"data");
    let mut messages: Vec<(&str, Vec<u8>)> = vec![("transport", transport)];
    p.clock.advance(common::S * 6);
    let init = p.a_initiates();
    messages.push(("initiation", init));

    for (name, msg) in &messages {
        for keep in 0..msg.len() {
            // Handshake messages of any wrong length are structurally
            // invalid; truncated transport is either structurally invalid
            // (< 32) or an AEAD forgery (≥ 32). All must reject.
            must_reject(
                &mut p.b,
                now,
                &msg[..keep],
                &format!("{name} truncated to {keep}"),
            );
        }
        let mut extended = msg.clone();
        extended.push(0);
        must_reject(&mut p.b, now, &extended, &format!("{name} extended"));
    }
}

#[test]
fn type_confusion_is_rejected() {
    let mut p = new_pair(63);
    let now = p.clock.now();
    let init = p.a_initiates();
    let resp = match p.deliver_to_b(&init).rx {
        Rx::Response(w) => w,
        other => panic!("{other:?}"),
    };
    // Relabel each message as every other type: length checks (and macs)
    // must kill all of them, on both ends.
    for (msg, target) in [(&init, &mut p.b), (&resp, &mut p.a)] {
        for t in [0u8, 1, 2, 3, 4, 5, 9, 255] {
            let mut bad = msg.clone();
            if bad[0] == t {
                continue;
            }
            bad[0] = t;
            must_reject(target, now, &bad, &format!("relabelled as {t}"));
        }
    }
}

#[test]
fn initiation_from_unknown_but_valid_peer_is_rejected() {
    // Mallory KNOWS B's public key (so mac1 verifies, and her identity
    // decrypts) but is not a configured peer.
    let mut p = new_pair(64);
    let now = p.clock.now();
    let b_pub = p.b.device.public_key();
    let (mallory_key, mallory_pub) = common::keypair(&mut p.rng);
    let mut mallory = common::side(
        mallory_key,
        b_pub,
        x_addr(),
        Some(b_addr()),
        None,
        None,
        &mut p.rng,
    );
    let init = mallory.initiate(now, &mut p.rng);

    // The device reveals who is calling. An embedder with a peer table
    // finds nobody under that key and drops it without touching any
    // tunnel…
    let mut copy = init.clone();
    match p.b.device.receive(now, x_addr(), false, &mut copy) {
        Incoming::Initiation(mut initiation) => {
            assert_eq!(initiation.peer_public(), None, "not identified yet");
            assert_eq!(initiation.src(), x_addr());
            let claimed = p.b.device.identify(&mut initiation).unwrap();
            assert_eq!(claimed, mallory_pub);
            assert_ne!(claimed, p.b.tunnel.peer_public());
            assert_eq!(initiation.peer_public(), Some(mallory_pub));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        p.b.tunnel.stats(),
        Default::default(),
        "no tunnel was involved"
    );

    // …and a tunnel handed an initiation that is not its peer's refuses.
    assert_eq!(
        must_reject(&mut p.b, now, &init, "mallory's initiation"),
        DropReason::UnknownPeer
    );
    assert_eq!(p.b.tunnel.stats().auth_failures, 1);
    assert_eq!(p.b.tunnel.stats().handshakes_responded, 0);
    assert!(!p.b.is_established(now));
}

#[test]
fn wrong_responder_initiation_fails_mac1_first() {
    // An initiation addressed to a *different* public key fails the cheap
    // mac1 check (counted separately from AEAD failures = the DoS path).
    let mut p = new_pair(65);
    let mut q = new_pair(66);
    let now = p.clock.now();
    let init = p.a_initiates();
    assert_eq!(
        must_reject(&mut q.b, now, &init, "initiation for another device"),
        DropReason::InvalidMac1
    );
    assert_eq!(q.b.device.stats().mac1_failures, 1);
    assert_eq!(
        q.b.device.stats().initiations,
        0,
        "it never got as far as the expensive work"
    );
    assert_eq!(q.b.tunnel.stats().auth_failures, 0);
}

#[test]
fn garbage_and_degenerate_datagrams() {
    let mut p = new_pair(67);
    p.establish();
    let now = p.clock.now();
    must_reject(&mut p.b, now, &[], "empty");
    must_reject(&mut p.b, now, &[1], "single byte");
    must_reject(&mut p.b, now, &[0; 4], "type zero");
    must_reject(&mut p.b, now, &[4, 0, 0], "truncated header");
    must_reject(&mut p.b, now, &[0xff; 4096], "4 KiB of 0xff");
    must_reject(&mut p.b, now, &[0x04; 31], "transport one byte short");
    // A datagram of zeros that parses as transport type … receiver 0.
    let mut zeros = vec![0u8; 64];
    zeros[0] = 4;
    must_reject(&mut p.b, now, &zeros, "all-zero transport");
    // Deterministic pseudo-random garbage, various lengths: must not
    // panic and must not be accepted (a random 16-byte mac1 forgery has
    // probability 2^-128).
    let mut rng = DeterministicRng::new(0xbad5eed);
    for len in [5usize, 31, 32, 64, 92, 147, 148, 149, 1500] {
        for _ in 0..50 {
            let mut g = vec![0u8; len];
            rng.fill(&mut g).unwrap();
            must_reject(&mut p.b, now, &g, "random garbage");
        }
    }
    // Still fully functional afterwards.
    p.assert_roundtrip_a_to_b(b"survived the garbage storm");
}

#[test]
fn cross_tunnel_datagrams_do_not_confuse_state() {
    // Two independent pairs; datagrams from one delivered into the other.
    let mut p = new_pair(68);
    let mut q = new_pair(69);
    p.establish();
    q.establish();
    let p_wire = p.seal_from_a(b"for p only");
    let q_wire = q.seal_from_a(b"for q only");
    let now = p.clock.now();
    // q.b sees p's datagram: unknown index or auth failure, never data.
    must_reject(&mut q.b, now, &p_wire, "p's datagram at q");
    must_reject(&mut p.b, now, &q_wire, "q's datagram at p");
    // Correct delivery still works.
    assert_eq!(&p.open_at_b(&p_wire)[..10], b"for p only");
    assert_eq!(&q.open_at_b(&q_wire)[..10], b"for q only");
}

#[test]
fn reflected_messages_are_rejected() {
    // Reflect every message straight back at its sender.
    let mut p = new_pair(70);
    let now = p.clock.now();
    let init = p.a_initiates();
    // A's own initiation reflected to A: mac1 is keyed by B's public key,
    // A expects macs keyed by A's public key → InvalidMac1.
    assert_eq!(
        must_reject(&mut p.a, now, &init, "reflected initiation"),
        DropReason::InvalidMac1
    );
    let resp = match p.deliver_to_b(&init).rx {
        Rx::Response(w) => w,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        must_reject(&mut p.b, now, &resp, "reflected response"),
        DropReason::InvalidMac1
    );
    assert_eq!(p.deliver_to_a(&resp).rx, Rx::HandshakeComplete);
    // Established transport reflected to its sender: the receiver index
    // was allocated by B's device, under B's index key; A's device decodes
    // it to nothing A owns, and even a collision would fail the AEAD.
    let data = p.seal_from_a(b"boomerang");
    must_reject(&mut p.a, now, &data, "reflected transport");
}

#[test]
fn errors_leave_tunnel_usable_under_interleaved_attack() {
    // Interleave valid traffic with attacks; the valid stream must be
    // completely unaffected.
    let mut p = new_pair(71);
    p.establish();
    let mut attacker_rng = DeterministicRng::new(0xa77ac);
    for i in 0..200u32 {
        let payload = format!("legit message {i}");
        p.assert_roundtrip_a_to_b(payload.as_bytes());
        // One attack per legit packet, cycling shapes.
        let now = p.clock.now();
        let attack: Vec<u8> = match i % 4 {
            0 => {
                let mut g = vec![0u8; 148];
                attacker_rng.fill(&mut g).unwrap();
                g[0] = 1;
                g[1] = 0;
                g[2] = 0;
                g[3] = 0;
                g
            }
            1 => {
                let mut t = p.seal_from_a(b"to corrupt");
                let len = t.len();
                t[len - 1] ^= 0xff;
                t
            }
            2 => vec![3u8, 0, 0, 0, 1, 2, 3, 4],
            _ => vec![2u8; 92],
        };
        must_reject(&mut p.b, now, &attack, "interleaved attack");
    }
    let s = p.b.tunnel.stats();
    let d = p.b.device.stats();
    assert_eq!(s.handshakes_completed, 1, "attacks must not force rekeys");
    assert_eq!(s.auth_failures, 50, "the corrupted transport packets");
    assert_eq!(d.mac1_failures, 50, "the random initiations");
    assert_eq!(
        d.malformed, 100,
        "the short cookie reply and the bad response"
    );
    assert_eq!(p.b.tunnel.endpoint(), Some(a_addr()));
}

/// A peer key that cannot work is refused when the tunnel is created,
/// not discovered at the first handshake: our own key (a tunnel to
/// ourselves), and the points of small order, with which every
/// Diffie-Hellman result is the same all-zero value whatever the private
/// key.
#[test]
fn a_peer_key_that_cannot_work_is_refused_at_configuration() {
    use wireguard_sans_io::{Device, Error, PeerConfig, PublicKey, StaticSecret};
    let mut rng = wireguard_sans_io::testing::DeterministicRng::new(77);
    let key = StaticSecret::generate(&mut rng).unwrap();
    let own_public = key.public_key();
    let device = Device::new(key, common::wall(), &mut rng).unwrap();
    let refused = |public: [u8; 32], rng: &mut wireguard_sans_io::testing::DeterministicRng| {
        device
            .tunnel(
                common::id(0),
                PeerConfig::new(PublicKey::from_bytes(public)),
                rng,
            )
            .err()
    };

    assert_eq!(
        refused(*own_public.as_bytes(), &mut rng),
        Some(Error::InvalidPublicKey),
        "our own public key"
    );

    // The small-order points of Curve25519 (and their non-canonical
    // encodings), as listed for instance in RFC 7748 §6.1's discussion
    // and libsodium's blocklist.
    let mut low_order: Vec<[u8; 32]> = Vec::new();
    let mut point = [0u8; 32]; // 0
    low_order.push(point);
    point[0] = 1; // 1
    low_order.push(point);
    low_order.push([
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ]);
    low_order.push([
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ]);
    // p − 1, p, p + 1 (little-endian; p = 2^255 − 19).
    for low_byte in [0xec, 0xed, 0xee] {
        let mut point = [0xffu8; 32];
        point[0] = low_byte;
        point[31] = 0x7f;
        low_order.push(point);
    }
    // The same points with the unused top bit set are the same points.
    for point in low_order.clone() {
        let mut with_top_bit = point;
        with_top_bit[31] |= 0x80;
        low_order.push(with_top_bit);
    }
    for point in low_order {
        assert_eq!(
            refused(point, &mut rng),
            Some(Error::InvalidPublicKey),
            "{point:02x?}"
        );
    }

    // An ordinary key is, of course, accepted.
    let other = StaticSecret::generate(&mut rng).unwrap().public_key();
    assert_eq!(refused(*other.as_bytes(), &mut rng), None);
}
