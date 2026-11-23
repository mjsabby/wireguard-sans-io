//! The DoS-mitigation cookie dance under load (whitepaper §5.3, §5.4.4,
//! §5.4.7, §6.6).
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;
use common::{Polled, Rx, a_addr, b_addr, new_pair, x_addr};
use wireguard_sans_io::{DropReason, Incoming, Received, SendReason, Timer, consts};

#[test]
fn full_cookie_dance_under_load() {
    let mut p = new_pair(30);
    let now = p.clock.now();

    // A initiates; B is under load and the initiation carries no mac2.
    let init1 = p.a_initiates();
    let cookie_reply = match p.b.recv_from(now, a_addr(), true, &init1, &mut p.rng).rx {
        Rx::CookieReply(w) => w,
        other => panic!("expected cookie reply, got {other:?}"),
    };
    assert_eq!(cookie_reply.len(), consts::COOKIE_REPLY_LEN);
    assert_eq!(cookie_reply[0], 3);
    assert_eq!(p.b.device.stats().cookies_sent, 1);
    assert_eq!(
        p.b.device.stats().initiations,
        0,
        "no Diffie-Hellman was done"
    );
    assert!(
        !p.b.is_established(now),
        "no session state from a cookie path"
    );
    assert_eq!(p.b.tunnel.stats().handshakes_responded, 0);

    // A stores the cookie quietly (§6.6: no immediate retransmission).
    assert_eq!(p.deliver_to_a(&cookie_reply).rx, Rx::CookieStored);
    assert_eq!(p.a.tunnel.stats().cookies_received, 1);
    assert_eq!(p.a.poll(now, &mut p.rng), Polled::Idle);

    // The Rekey-Timeout retransmission now carries mac2 and B (still
    // under load) accepts and responds.
    let retry_at = p.clock.advance(consts::REKEY_TIMEOUT + 400_000_000);
    let init2 = match p.a.poll(retry_at, &mut p.rng) {
        Polled::Transmit(w, SendReason::HandshakeRetransmit, _) => w,
        other => panic!("expected retransmit, got {other:?}"),
    };
    let mac2 = &init2[consts::HANDSHAKE_INITIATION_LEN - 16..];
    assert!(mac2.iter().any(|&b| b != 0), "retry must carry mac2");
    let resp = match p
        .b
        .recv_from(retry_at, a_addr(), true, &init2, &mut p.rng)
        .rx
    {
        Rx::Response(w) => w,
        other => panic!("expected response, got {other:?}"),
    };
    assert_eq!(p.deliver_to_a(&resp).rx, Rx::HandshakeComplete);
}

#[test]
fn mac2_is_bound_to_the_remote_address() {
    let mut p = new_pair(31);
    let now = p.clock.now();
    let init1 = p.a_initiates();
    let cookie_reply = match p.b.recv_from(now, a_addr(), true, &init1, &mut p.rng).rx {
        Rx::CookieReply(w) => w,
        other => panic!("{other:?}"),
    };
    assert_eq!(p.deliver_to_a(&cookie_reply).rx, Rx::CookieStored);
    let retry_at = p.clock.advance(consts::REKEY_TIMEOUT + 400_000_000);
    let init2 = match p.a.poll(retry_at, &mut p.rng) {
        Polled::Transmit(w, _, _) => w,
        other => panic!("{other:?}"),
    };
    // Same datagram "arriving" from a different source address — or the
    // same address and another port: the cookie (and thus mac2) no longer
    // proves IP ownership → B answers with a fresh cookie reply rather
    // than doing the DH work.
    let other_port: std::net::SocketAddr = "192.0.2.1:51821".parse().unwrap();
    for src in [x_addr(), other_port] {
        match p.b.recv_from(retry_at, src, true, &init2, &mut p.rng).rx {
            Rx::CookieReply(w) => assert_eq!(w[0], 3, "cookie reply, not response"),
            other => panic!("{src}: {other:?}"),
        }
    }
    // From the right address it is processed — also when a dual-stack
    // socket reports that address in its IPv4-mapped IPv6 form.
    let mapped: std::net::SocketAddr = "[::ffff:192.0.2.1]:51820".parse().unwrap();
    match p.b.recv_from(retry_at, mapped, true, &init2, &mut p.rng).rx {
        Rx::Response(w) => assert_eq!(w[0], 2, "handshake response"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn not_under_load_ignores_missing_mac2() {
    let mut p = new_pair(32);
    p.establish();
    p.assert_roundtrip_a_to_b(b"no cookies involved");
    assert_eq!(p.a.tunnel.stats().cookies_received, 0);
    assert_eq!(p.b.device.stats().cookies_sent, 0);
    assert_eq!(p.b.device.stats().cookies_required, 0);
}

#[test]
fn expired_cookies_stop_filling_mac2() {
    let mut p = new_pair(33);
    let now = p.clock.now();
    let init1 = p.a_initiates();
    let cookie_reply = match p.b.recv_from(now, a_addr(), true, &init1, &mut p.rng).rx {
        Rx::CookieReply(w) => w,
        other => panic!("{other:?}"),
    };
    assert_eq!(p.deliver_to_a(&cookie_reply).rx, Rx::CookieStored);
    // One second before the cookie expires it is still used…
    let almost = p.clock.advance(consts::COOKIE_LIFETIME - common::S);
    let init = p.a.initiate(almost, &mut p.rng);
    assert!(
        init[consts::HANDSHAKE_INITIATION_LEN - 16..]
            .iter()
            .any(|&b| b != 0),
        "fresh cookie must be used"
    );
    // …and two minutes after it was received it is not: the next
    // initiation goes out with mac2 = 0 again.
    let later = p.clock.advance(6 * common::S);
    let init = p.a.initiate(later, &mut p.rng);
    assert!(
        init[consts::HANDSHAKE_INITIATION_LEN - 16..]
            .iter()
            .all(|&b| b == 0),
        "expired cookie must not be used"
    );
}

#[test]
fn forged_cookie_replies_are_rejected_and_change_nothing() {
    let mut p = new_pair(34);
    let now = p.clock.now();
    let init = p.a_initiates();
    let cookie_reply = match p.b.recv_from(now, a_addr(), true, &init, &mut p.rng).rx {
        Rx::CookieReply(w) => w,
        other => panic!("{other:?}"),
    };
    // Flip each byte of the encrypted section: all rejected.
    for byte in 8..consts::COOKIE_REPLY_LEN {
        let mut bad = cookie_reply.clone();
        bad[byte] ^= 1;
        assert_eq!(
            p.deliver_to_a(&bad).rx,
            Rx::Dropped(DropReason::InvalidCookie),
            "byte {byte}"
        );
    }
    assert_eq!(p.a.tunnel.stats().cookies_received, 0);
    // A cookie reply for an unknown receiver index is rejected earlier.
    let mut bad = cookie_reply.clone();
    bad[4] ^= 0x55;
    assert_eq!(
        p.deliver_to_a(&bad).rx,
        Rx::Dropped(DropReason::UnknownIndex)
    );
    // The real one still works after all that.
    assert_eq!(p.deliver_to_a(&cookie_reply).rx, Rx::CookieStored);
}

#[test]
fn under_load_initiations_with_valid_mac2_skip_the_dance() {
    // Once A has a fresh cookie, every handshake message it sends within
    // the cookie lifetime is processed by a loaded B on first delivery.
    let mut p = new_pair(35);
    let now = p.clock.now();
    let init1 = p.a_initiates();
    let reply = match p.b.recv_from(now, a_addr(), true, &init1, &mut p.rng).rx {
        Rx::CookieReply(w) => w,
        other => panic!("{other:?}"),
    };
    assert_eq!(p.deliver_to_a(&reply).rx, Rx::CookieStored);
    let t1 = p.clock.advance(consts::REKEY_TIMEOUT + 400_000_000);
    let init2 = match p.a.poll(t1, &mut p.rng) {
        Polled::Transmit(w, _, _) => w,
        other => panic!("{other:?}"),
    };
    let resp = match p.b.recv_from(t1, a_addr(), true, &init2, &mut p.rng).rx {
        Rx::Response(w) => w,
        other => panic!("{other:?}"),
    };
    // Note: A consumes the response NOT under load. (A loaded receiver
    // would be entitled to demand mac2 on the response too — covered by
    // `loaded_initiator_cookies_responses`.)
    assert_eq!(p.deliver_to_a(&resp).rx, Rx::HandshakeComplete);
    assert!(p.a.is_established(t1));
    assert_eq!(
        p.b.device.stats().cookies_sent,
        1,
        "only the first round needed a cookie"
    );
}

#[test]
fn loaded_initiator_cookies_responses() {
    // The under-load mac2 rule applies to handshake *responses* as well
    // (whitepaper §5.3: "either an initiation or a response handshake
    // message"): a loaded initiator answers a mac2-less response with a
    // cookie reply rather than finishing the handshake.
    let mut p = new_pair(36);
    let now = p.clock.now();
    let init = p.a_initiates();
    let resp = match p.deliver_to_b(&init).rx {
        Rx::Response(w) => w,
        other => panic!("{other:?}"),
    };
    match p.a.recv_from(now, b_addr(), true, &resp, &mut p.rng).rx {
        Rx::CookieReply(w) => assert_eq!(w[0], 3, "cookie reply to the responder"),
        other => panic!("{other:?}"),
    }
    assert!(
        !p.a.is_established(now),
        "handshake deliberately not completed"
    );
    // The in-flight handshake is still alive: the same response delivered
    // when no longer loaded completes it.
    assert_eq!(p.deliver_to_a(&resp).rx, Rx::HandshakeComplete);
}

/// The responder stores the cookie it is sent for its *response* and uses
/// it on the next handshake message it sends.
#[test]
fn responder_uses_a_cookie_received_for_its_response() {
    let mut p = new_pair(37);
    let now = p.clock.now();
    let init = p.a_initiates();
    let resp = match p.deliver_to_b(&init).rx {
        Rx::Response(w) => w,
        other => panic!("{other:?}"),
    };
    // A is loaded: it answers B's response with a cookie reply…
    let cookie = match p.a.recv_from(now, b_addr(), true, &resp, &mut p.rng).rx {
        Rx::CookieReply(w) => w,
        other => panic!("{other:?}"),
    };
    // …which B accepts (bound to the mac1 of its response).
    assert_eq!(p.deliver_to_b(&cookie).rx, Rx::CookieStored);
    // B's next handshake message — its own initiation, 5 s later — carries
    // mac2, and loaded A processes it at once.
    let later = p.clock.advance(6 * common::S);
    let b_init = p.b.initiate(later, &mut p.rng);
    assert!(b_init[132..].iter().any(|&b| b != 0), "mac2 must be filled");
    assert!(matches!(
        p.a.recv_from(later, b_addr(), true, &b_init, &mut p.rng).rx,
        Rx::Response(_)
    ));
}

/// A cookie reply does not authenticate its sender. Accepting one must
/// not move the peer's endpoint, must not count as hearing from the peer,
/// and the reply to an unauthenticated handshake message must go back to
/// where that message came from — not to the peer.
#[test]
fn cookie_messages_are_not_authenticated_events() {
    let mut p = new_pair(38);
    p.establish();
    // A has unanswered data outstanding, so its dead-peer timer runs.
    let _lost = p.seal_from_a(b"unanswered");
    let dead_peer_deadline = p.a.tunnel.timer(Timer::NewHandshake);
    assert!(dead_peer_deadline.is_some());

    // A starts a rekey; B (under load) demands a cookie.
    let now = p.clock.advance(6 * common::S);
    let init = p.a.initiate(now, &mut p.rng);
    let cookie = match p.b.recv_from(now, a_addr(), true, &init, &mut p.rng).rx {
        Rx::CookieReply(w) => w,
        other => panic!("{other:?}"),
    };
    // The cookie reply reaches A from some other address entirely.
    let info = p.a.recv_from(now, x_addr(), false, &cookie, &mut p.rng);
    assert_eq!(info.rx, Rx::CookieStored);
    assert!(!info.endpoint_changed);
    assert!(!info.session_established);
    assert_eq!(
        p.a.tunnel.endpoint(),
        Some(b_addr()),
        "endpoint must not move"
    );
    assert_eq!(
        p.a.tunnel.timer(Timer::NewHandshake),
        dead_peer_deadline,
        "a cookie reply is not a sign of life"
    );

    // And on B: a handshake message from an outsider, under load, yields a
    // cookie reply addressed to the outsider, leaving B's endpoint for A
    // exactly where it was.
    let mut copy = init.clone();
    let mut out = [0u8; 128];
    let handled =
        p.b.device
            .receive_for(
                &mut p.b.tunnel,
                now,
                x_addr(),
                true,
                &mut copy,
                &mut out,
                &mut p.rng,
            )
            .unwrap();
    match &handled.received {
        Received::CookieReply(tx) => assert_eq!(tx.dst, x_addr()),
        other => panic!("{other:?}"),
    }
    assert!(!handled.received.is_authenticated());
    assert!(!handled.endpoint_changed);
    assert_eq!(p.b.tunnel.endpoint(), Some(a_addr()));
}

/// The two-step path (`Device::receive` + `Device::cookie_reply`) gives
/// the embedder the choice of not answering at all.
#[test]
fn cookie_challenge_can_be_answered_or_ignored() {
    let mut p = new_pair(39);
    let now = p.clock.now();
    let init = p.a_initiates();
    let mut copy = init.clone();
    let challenge = match p.b.device.receive(now, a_addr(), true, &mut copy) {
        Incoming::CookieRequired(c) => c,
        other => panic!("{other:?}"),
    };
    assert_eq!(challenge.src(), a_addr());
    assert_eq!(p.b.device.stats().cookies_required, 1);
    assert_eq!(p.b.device.stats().cookies_sent, 0, "nothing sent yet");
    // A too-small buffer is a local fault and consumes nothing.
    let mut tiny = [0u8; 63];
    assert!(
        p.b.device
            .cookie_reply(now, &challenge, &mut tiny, &mut p.rng)
            .is_err()
    );
    let mut out = [0u8; 64];
    let reply =
        p.b.device
            .cookie_reply(now, &challenge, &mut out, &mut p.rng)
            .unwrap();
    assert_eq!(reply.dst, a_addr());
    assert_eq!(reply.datagram.len(), 64);
    let reply = reply.datagram.to_vec();
    assert_eq!(p.b.device.stats().cookies_sent, 1);
    assert_eq!(p.deliver_to_a(&reply).rx, Rx::CookieStored);
}

/// A cookie opens the under-load gate for a bounded time only — whether
/// or not the device has minted anything since. Someone who proved their
/// address during one load episode must not find the gate open hours
/// later. (The cookie secret used to be replaced only when the next
/// cookie was minted, so across a quiet period an old cookie stayed
/// valid indefinitely.)
#[test]
fn old_cookies_stop_opening_the_gate() {
    use wireguard_sans_io::Ticks;
    let mut p = new_pair(40);
    let drawn = p.clock.now();
    let init1 = p.a_initiates();
    let cookie_reply = match p.b.recv_from(drawn, a_addr(), true, &init1, &mut p.rng).rx {
        Rx::CookieReply(w) => w,
        other => panic!("{other:?}"),
    };
    assert_eq!(p.deliver_to_a(&cookie_reply).rx, Rx::CookieStored);
    let retry_at = p.clock.advance(consts::REKEY_TIMEOUT + 400_000_000);
    let with_mac2 = match p.a.poll(retry_at, &mut p.rng) {
        Polled::Transmit(w, SendReason::HandshakeRetransmit, _) => w,
        other => panic!("{other:?}"),
    };

    // Does the gate open for this message at `at`? (Open: the device does
    // the Diffie-Hellman and hands the initiation out. Closed: it asks
    // for a cookie.)
    let mut gate_opens = |at: Ticks| {
        let mut copy = with_mac2.clone();
        match p.b.device.receive(at, a_addr(), true, &mut copy) {
            Incoming::Initiation(_) => true,
            Incoming::CookieRequired(_) => false,
            other => panic!("{other:?}"),
        }
    };
    assert!(gate_opens(retry_at));
    let dies = drawn.add_nanos(consts::COOKIE_LIFETIME + consts::COOKIE_SECRET_GRACE);
    assert!(gate_opens(Ticks::from_nanos(dies.nanos() - 1)));
    // A lifetime and the grace after the secret was drawn it is over,
    // although B has not minted (and so not rotated) anything in between.
    assert!(!gate_opens(dies));
    assert!(!gate_opens(Ticks::from_secs(3 * 3600)));

    // A new load episode hours later mints a fresh cookie, which moves
    // the old secret into the "previous" slot: still closed.
    let later = Ticks::from_secs(3 * 3600);
    let mut copy = with_mac2.clone();
    let challenge = match p.b.device.receive(later, a_addr(), true, &mut copy) {
        Incoming::CookieRequired(c) => c,
        other => panic!("{other:?}"),
    };
    let mut out = [0u8; 64];
    p.b.device
        .cookie_reply(later, &challenge, &mut out, &mut p.rng)
        .unwrap();
    let mut copy = with_mac2.clone();
    assert!(matches!(
        p.b.device.receive(later, a_addr(), true, &mut copy),
        Incoming::CookieRequired(_)
    ));
}

/// The device counts time too (cookies age by it), and for it as well an
/// instant out of range is not a time. Taken at face value, one such
/// reading would date the cookie secret at the end of time: it would
/// never be replaced again, and every cookie minted from it would open
/// the gate for as long as the process lives.
#[test]
fn an_out_of_range_instant_does_not_keep_cookies_alive() {
    use wireguard_sans_io::Ticks;
    let absurd = Ticks::from_secs(1_763_000_000_000); // milliseconds, passed as seconds
    assert_eq!(absurd.nanos(), u64::MAX);
    let mut p = new_pair(41);
    let drawn = p.clock.now();
    let init1 = p.a_initiates();
    // B is under load — and its embedder's clock is wrong at this moment.
    let cookie_reply = match p.b.recv_from(absurd, a_addr(), true, &init1, &mut p.rng).rx {
        Rx::CookieReply(w) => w,
        other => panic!("{other:?}"),
    };
    assert_eq!(p.deliver_to_a(&cookie_reply).rx, Rx::CookieStored);
    let retry_at = p.clock.advance(consts::REKEY_TIMEOUT + 400_000_000);
    let with_mac2 = match p.a.poll(retry_at, &mut p.rng) {
        Polled::Transmit(w, SendReason::HandshakeRetransmit, _) => w,
        other => panic!("{other:?}"),
    };
    let mut gate_opens = |at: Ticks| {
        let mut copy = with_mac2.clone();
        match p.b.device.receive(at, a_addr(), true, &mut copy) {
            Incoming::Initiation(_) => true,
            Incoming::CookieRequired(_) => false,
            other => panic!("{other:?}"),
        }
    };
    assert!(gate_opens(retry_at));
    // The wrong reading again: time stands still, the cookie is as good
    // as it was a moment ago.
    assert!(gate_opens(absurd));
    // And it dies when it should: a lifetime and the grace after its
    // secret was drawn, by the instants that were times.
    let dies = drawn.add_nanos(consts::COOKIE_LIFETIME + consts::COOKIE_SECRET_GRACE);
    assert!(gate_opens(Ticks::from_nanos(dies.nanos() - 1)));
    assert!(!gate_opens(dies));
    assert!(!gate_opens(Ticks::from_secs(3 * 3600)));
    assert!(!gate_opens(absurd));
}
