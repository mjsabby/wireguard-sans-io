//! Behaviour that used to be pinned by nothing: each of these tests fails
//! for a defect that the rest of the suite let through when it was planted
//! (found by mutation testing; the test says which defect).
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;
use common::{Opts, Polled, Rx, S, new_pair, new_pair_opts};
use wireguard_sans_io::consts::{REKEY_AFTER_TIME, REKEY_AFTER_TIME_RECV, REKEY_ATTEMPT_TIME};
use wireguard_sans_io::{Encapsulated, SendReason, Timer};

/// The defect: the receive path asks for a new handshake at
/// Rekey-After-Time (120 s) instead of Reject-After-Time −
/// Keepalive-Timeout − Rekey-Timeout (165 s). Whitepaper §6.2; Linux
/// receive.c `keep_key_fresh`.
#[test]
fn receiving_does_not_start_a_rekey_before_165_seconds() {
    let mut p = new_pair(0x5601);
    p.establish();
    const { assert!(REKEY_AFTER_TIME < REKEY_AFTER_TIME_RECV) };
    // 130 s: past Rekey-After-Time, well before the receive-path limit.
    p.clock.advance(130 * S);
    let wire = p.seal_from_b(b"still here");
    let _ = p.open_at_a(&wire);
    let (wires, events) = p.a.drain(p.clock.now(), &mut p.rng);
    assert!(
        wires.is_empty() && events.is_empty(),
        "the initiator started a handshake on RECEIVING at session age 130 s: {wires:?}"
    );
    assert_eq!(p.a.tunnel.stats().handshakes_initiated, 1);
    assert_eq!(p.a.tunnel.timer(Timer::SendInitiation), None);
}

/// The defect: `Tunnel::encapsulate` does not zero the padding, and
/// whatever the caller's buffer held before is encrypted and sent.
/// Whitepaper §5.4.6 ("padded with zeros"); Linux send.c `encrypt_packet`
/// (`memset(skb_tail_pointer(trailer), 0, padding_len)`).
#[test]
fn encapsulate_zeroes_the_padding_in_a_dirty_buffer() {
    let mut p = new_pair(0x5602);
    p.establish();
    let now = p.clock.now();
    // What a caller's reused output buffer looks like: not zero.
    let mut dirty = [0xAAu8; 256];
    let wire = match p.a.tunnel.encapsulate(now, b"x", &mut dirty).unwrap() {
        Encapsulated::Transport(tx) => tx.datagram.to_vec(),
        other => panic!("{other:?}"),
    };
    let got = p.open_at_b(&wire);
    assert_eq!((got.len(), got[0]), (16, b'x'));
    assert!(
        got[1..].iter().all(|&b| b == 0),
        "stale bytes of the caller's buffer were encrypted and sent as padding: {:02x?}",
        &got[1..]
    );
}

/// The defect: `>` for `>=` on Rekey-Attempt-Time. At exactly 90 s the
/// attempt is over, not retransmitted once more.
#[test]
fn an_attempt_is_given_up_at_exactly_rekey_attempt_time() {
    let mut p = new_pair(0x5603);
    let t0 = p.clock.now();
    let _init = p.a_initiates();
    let at = p.clock.advance(REKEY_ATTEMPT_TIME);
    assert_eq!(at.since(t0), REKEY_ATTEMPT_TIME);
    assert_eq!(
        p.a.poll(at, &mut p.rng),
        Polled::HandshakeExpired,
        "at exactly Rekey-Attempt-Time the attempt must be abandoned, not retransmitted"
    );
}

/// The defect: a keepalive that was owed before any session existed is
/// not sent when the tunnel ends up as the *responder* of the session.
#[test]
fn a_keepalive_owed_at_startup_goes_out_when_we_end_up_responder() {
    let mut p = new_pair_opts(
        0x5604,
        Opts {
            keepalive_b: Some(25),
            ..Opts::default()
        },
    );
    let now = p.clock.now();
    // B (persistent keepalive) owes "a handshake followed by a keepalive"
    // from construction, but A's initiation gets there first.
    let init = p.a_initiates();
    let Rx::Response(resp) = p.deliver_to_b(&init).rx else {
        panic!("B did not answer")
    };
    assert_eq!(p.deliver_to_a(&resp).rx, Rx::HandshakeComplete);
    let (wires, _) = p.a.drain(now, &mut p.rng);
    assert_eq!(wires.len(), 1, "A's confirming keepalive");
    assert!(p.deliver_to_b(&wires[0].0).session_established);
    let (wires, _) = p.b.drain(now, &mut p.rng);
    assert!(
        wires
            .iter()
            .any(|(w, why)| *why == SendReason::Keepalive && w.len() == 32),
        "the keepalive B owed did not leave when its session became usable: {wires:?}"
    );
}

/// The defect: giving up a handshake keeps the keepalive that was waiting
/// for it. Whitepaper §6.4: "…and clear all existing packets queued up to
/// be sent".
#[test]
fn giving_up_drops_the_keepalive_that_was_waiting_for_the_session() {
    let mut p = new_pair(0x5605);
    p.establish();
    // A sends data when the session is 175 s old; B receives it and owes
    // a passive keepalive at 185 s — when the session is past
    // Reject-After-Time, so the keepalive is staged and B (the responder)
    // starts a handshake for it. From here on the network is dead:
    // nothing either side emits from poll() is delivered.
    p.clock.advance(175 * S);
    let wire = p.seal_from_a(b"last words");
    let _ = p.open_at_b(&wire);
    let mut b_gave_up = false;
    for _ in 0..400 {
        let now = p.clock.now();
        let _ = p.a.drain(now, &mut p.rng);
        let (_wires, events) = p.b.drain(now, &mut p.rng);
        if events.contains(&"handshake_expired") {
            b_gave_up = true;
            break;
        }
        let next = [p.a.tunnel.next_wake(), p.b.tunnel.next_wake()]
            .into_iter()
            .flatten()
            .min();
        match next {
            Some(wake) => {
                p.clock.set(wake);
            }
            None => break,
        }
    }
    assert!(b_gave_up, "B never gave up its handshake");
    assert!(p.b.tunnel.stats().handshakes_initiated >= 2, "B did try");
    // Let A's own attempt run out too, then bring the network back: A
    // initiates, B answers and is confirmed by A's keepalive.
    p.clock.advance(120 * S);
    let now = p.clock.now();
    let _ = p.a.drain(now, &mut p.rng);
    let _ = p.b.drain(now, &mut p.rng);
    p.clock.advance(10 * S);
    let now = p.clock.now();
    let init = p.a_initiates();
    let Rx::Response(resp) = p.deliver_to_b(&init).rx else {
        panic!("B did not answer")
    };
    assert_eq!(p.deliver_to_a(&resp).rx, Rx::HandshakeComplete);
    let (wires, _) = p.a.drain(now, &mut p.rng);
    assert_eq!(wires.len(), 1, "A's confirming keepalive");
    assert!(p.deliver_to_b(&wires[0].0).session_established);
    let (wires, _) = p.b.drain(now, &mut p.rng);
    assert!(
        wires.is_empty(),
        "B sent the keepalive that was queued for the attempt it gave up: {wires:?}"
    );
}
