//! Security regression tests. These previously demonstrated bugs; they
//! now lock in the fixes.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;
use common::{Opts, Polled, Rx, Sim, Tx, Who, a_addr, b_addr, new_pair, new_pair_opts, x_addr};
use wireguard_sans_io::crypto::blake2s;
use wireguard_sans_io::{DropReason, SendReason};

// ============================================================================
// A mac2 forged against the all-zero `previous` cookie secret must be
// rejected; the under-load responder must send a cookie reply, not run the
// full Noise handshake.
// ============================================================================
#[test]
fn cookie_jar_rejects_all_zero_previous_forgery() {
    let mut p = new_pair(7);
    let now = p.clock.now();
    // A third party who knows the responder's pubkey but holds a different
    // static key.
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

    // Step 1: prime the responder's cookie jar.
    let init1 = mallory.initiate(now, &mut p.rng);
    assert!(matches!(
        p.b.recv_from(now, x_addr(), true, &init1, &mut p.rng).rx,
        Rx::CookieReply(_)
    ));
    assert_eq!(p.b.device.stats().cookies_sent, 1);

    // Step 2: forge mac2 against the all-zero key, ignoring the cookie
    // reply. The cookie is Mac(secret, IP ‖ port).
    let now2 = p.clock.advance(6 * common::S);
    let init2 = mallory.initiate(now2, &mut p.rng);
    let mut forged = init2.clone();
    let remote: [u8; 6] = [203, 0, 113, 66, 0x11, 0x5c]; // x_addr() = 203.0.113.66:4444
    assert_eq!(x_addr().port(), 0x115c);
    let forged_cookie = blake2s::mac(&[0u8; 32], &[remote.as_slice()]);
    let forged_mac2 = blake2s::mac(&forged_cookie, &[&forged[..132]]);
    forged[132..148].copy_from_slice(&forged_mac2);

    // Step 3: under load, the forgery must be REJECTED → cookie reply,
    // not full handshake processing.
    assert!(
        matches!(
            p.b.recv_from(now2, x_addr(), true, &forged, &mut p.rng).rx,
            Rx::CookieReply(_)
        ),
        "forged mac2 must not bypass under-load protection"
    );
    assert_eq!(
        p.b.device.stats().cookies_sent,
        2,
        "responder must answer the forgery with a (cheap) cookie reply"
    );
    assert_eq!(
        p.b.device.stats().initiations,
        0,
        "no Diffie-Hellman was done"
    );
}

// ============================================================================
// Handshake-response mac1 is verified before the receiver index is looked
// at, so an off-path attacker can't timing-probe the in-flight index.
// ============================================================================
#[test]
fn response_mac1_checked_before_index() {
    let mut p = new_pair(11);
    let now = p.clock.now();
    // Put a handshake in flight so an index *could* match.
    let init = p.a_initiates();
    // A 92-byte response with garbage everywhere (mac1 invalid): rejected
    // for its mac1 whatever the receiver index says — including the index
    // that IS in flight.
    for index in [[0u8; 4], [0xff; 4], init[4..8].try_into().unwrap()] {
        let mut resp = [0u8; 92];
        resp[0] = 2; // type
        resp[8..12].copy_from_slice(&index);
        assert_eq!(
            p.a.recv_from(now, b_addr(), false, &resp, &mut p.rng).rx,
            Rx::Dropped(DropReason::InvalidMac1)
        );
    }
    assert_eq!(p.a.device.stats().mac1_failures, 3);
    assert_eq!(
        p.a.tunnel.stats().auth_failures,
        0,
        "the tunnel never saw them"
    );
}

// ============================================================================
// The peer's endpoint must only move on authenticated messages. A cookie
// reply is produced for a handshake message that merely carries a valid
// mac1 — which anyone who knows our PUBLIC key can make — so it must never
// redirect the tunnel. (An earlier driver treated every reply as proof of
// the peer's address: thirty such initiations from an unrelated socket
// diverted the tunnel's traffic to that socket.)
// ============================================================================
#[test]
fn outsider_with_only_our_public_key_cannot_redirect_traffic() {
    let mut p = new_pair(12);
    p.establish();
    p.assert_roundtrip_a_to_b(b"baseline");
    let now = p.clock.now();

    // Thirty mac1-valid initiations from throwaway identities, under load.
    for _ in 0..30 {
        let (key, _) = common::keypair(&mut p.rng);
        let mut throwaway = common::side(
            key,
            p.b.device.public_key(),
            x_addr(),
            Some(b_addr()),
            None,
            None,
            &mut p.rng,
        );
        let init = throwaway.initiate(now, &mut p.rng);
        let info = p.b.recv_from(now, x_addr(), true, &init, &mut p.rng);
        assert!(matches!(info.rx, Rx::CookieReply(_)));
        assert!(!info.endpoint_changed);
    }
    assert_eq!(p.b.tunnel.endpoint(), Some(a_addr()));
    // B's next packet still goes to A, and A receives it.
    let mut buf = [0u8; 128];
    let wire = match p
        .b
        .tunnel
        .encapsulate(now, b"for a only", &mut buf)
        .unwrap()
    {
        wireguard_sans_io::Encapsulated::Transport(tx) => {
            assert_eq!(tx.dst, a_addr());
            tx.datagram.to_vec()
        }
        other => panic!("{other:?}"),
    };
    assert_eq!(&p.open_at_a(&wire)[..10], b"for a only");
}

// ============================================================================
// A side that was holding a packet (no session) and then ends up as the
// RESPONDER of the handshake that completes must be told that it can send
// now. (An earlier driver only learned of sessions it had initiated, and
// left such a packet queued while later packets overtook it.)
// ============================================================================
#[test]
fn responder_side_is_told_when_its_session_is_established() {
    let mut p = new_pair(13);
    let now = p.clock.now();
    // B wants to send, has no session: it asks for a handshake, and its
    // initiation is lost.
    assert_eq!(p.b.send(now, b"queued by the embedder"), Tx::NoSession);
    assert!(matches!(
        p.b.poll(now, &mut p.rng),
        Polled::Transmit(_, SendReason::HandshakeInitiation, _)
    ));
    // Meanwhile A initiates; B answers as responder.
    let init = p.a_initiates();
    let info = p.deliver_to_b(&init);
    let resp = match info.rx {
        Rx::Response(w) => w,
        other => panic!("{other:?}"),
    };
    assert!(!info.session_established);
    assert_eq!(p.deliver_to_a(&resp).rx, Rx::HandshakeComplete);
    let confirm = match p.a.poll(now, &mut p.rng) {
        Polled::Transmit(w, SendReason::Keepalive, _) => w,
        other => panic!("{other:?}"),
    };
    // A's confirming keepalive — not data, and B is not the initiator —
    // is where B learns the session is usable.
    let info = p.deliver_to_b(&confirm);
    assert_eq!(info.rx, Rx::Keepalive);
    assert!(info.session_established, "the responder must be told");
    // The held packet can go out now, ahead of anything newer.
    let wire = p.seal_from_b(b"queued by the embedder");
    assert_eq!(&p.open_at_a(&wire)[..22], b"queued by the embedder");
}

// ============================================================================
// A peer that only ever sends keepalives (persistent keepalive behind a
// NAT that re-maps it) still roams: a keepalive is an authenticated
// message like any other.
// ============================================================================
#[test]
fn keepalive_only_peer_roams() {
    let mut s = Sim::with_opts(
        14,
        Opts {
            keepalive_a: Some(25),
            b_without_endpoint: true,
            ..Opts::default()
        },
    );
    s.run_until(common::S);
    assert_eq!(s.p.b.tunnel.endpoint(), Some(a_addr()));
    // The NAT in front of A picks a new mapping; A sends nothing but its
    // persistent keepalives.
    let remapped: std::net::SocketAddr = "192.0.2.1:40000".parse().unwrap();
    s.p.a.addr = remapped;
    s.run_until(30 * common::S);
    assert_eq!(
        s.count(Who::A, SendReason::PersistentKeepalive, 0, u64::MAX),
        1
    );
    assert_eq!(
        s.p.b.tunnel.endpoint(),
        Some(remapped),
        "the server must follow the keepalive's source address"
    );
    let _ = new_pair_opts(0, Opts::default());
}

// ============================================================================
// `{:?}` of what a receive call returns ends up in logs. It must say how
// much was received, not what: a decrypted packet printed its bytes
// through the derived `Debug` of `Received::Data` (and so of `Handled`).
// ============================================================================
#[test]
fn debug_output_gives_the_size_of_a_payload_never_its_bytes() {
    use wireguard_sans_io::{Encapsulated, Incoming};
    let mut p = new_pair(9);
    p.establish();
    let now = p.clock.now();
    // 48 bytes whose values are unmistakable in decimal and in hex.
    let payload: Vec<u8> = (0..48u8).map(|i| 200 + i).collect();
    let leaks = |shown: &str| {
        payload.windows(2).any(|w| {
            shown.contains(&format!("{}, {}", w[0], w[1]))
                || shown.contains(&format!("{:02x}{:02x}", w[0], w[1]))
                || shown.contains(&format!("{:02X}{:02X}", w[0], w[1]))
        })
    };
    assert!(leaks(&format!("{payload:?}")), "the check can see a leak");

    let wire = match p.a.tunnel.encapsulate(now, &payload, &mut [0u8; 128]) {
        Ok(Encapsulated::Transport(tx)) => {
            // What goes out is ciphertext; its Debug is destination and size.
            let shown = format!("{tx:?}");
            assert_eq!(
                shown,
                format!("Transmit {{ dst: {}, datagram: 80 bytes }}", b_addr())
            );
            tx.datagram.to_vec()
        }
        other => panic!("{other:?}"),
    };

    // Routed, not yet decrypted.
    let mut copy = wire.clone();
    match p.b.device.receive(now, a_addr(), false, &mut copy) {
        Incoming::ForPeer(_, packet) => {
            let shown = format!("{packet:?} {packet:#?}");
            assert!(shown.contains("body: 64 bytes"), "{shown}");
            let handled = p.b.tunnel.handle(now, a_addr(), packet).unwrap();
            // Decrypted: the result, and everything that wraps it.
            for shown in [
                format!("{handled:?}"),
                format!("{handled:#?}"),
                format!("{:?}", handled.received),
                format!("{:#?}", handled.received),
            ] {
                assert!(shown.contains("Data(48 bytes)"), "{shown}");
                assert!(!leaks(&shown), "{shown}");
            }
        }
        other => panic!("{other:?}"),
    }
}
