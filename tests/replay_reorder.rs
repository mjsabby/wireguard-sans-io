//! Replay protection and packet reordering over the wire, plus handshake
//! replay defences (timestamps, response one-shot).
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;
use common::{Rx, new_pair};
use wireguard_sans_io::DropReason;

#[test]
fn duplicate_transport_datagrams_rejected() {
    let mut p = new_pair(20);
    p.establish();
    let wire = p.seal_from_a(b"once only");
    let got = p.open_at_b(&wire);
    assert_eq!(&got[..9], b"once only");
    // Byte-identical replay: rejected by the replay window, even though
    // the AEAD would verify.
    assert_eq!(p.deliver_to_b(&wire).rx, Rx::Dropped(DropReason::Replay));
    assert_eq!(p.b.tunnel.stats().replays_dropped, 1);
    // And again later in time.
    p.clock.advance(common::S);
    assert_eq!(p.deliver_to_b(&wire).rx, Rx::Dropped(DropReason::Replay));
}

#[test]
fn reordered_delivery_within_window_is_accepted() {
    let mut p = new_pair(21);
    p.establish();
    // Encrypt 64 datagrams, deliver them in reverse order.
    let wires: Vec<(usize, Vec<u8>)> = (0..64)
        .map(|i| {
            let payload = format!("packet number {i:03}");
            (i, p.seal_from_a(payload.as_bytes()))
        })
        .collect();
    for (i, wire) in wires.iter().rev() {
        let got = p.open_at_b(wire);
        assert_eq!(&got[..17], format!("packet number {i:03}").as_bytes());
    }
    // Every single one replayed afterwards is rejected.
    for (_, wire) in &wires {
        assert_eq!(p.deliver_to_b(wire).rx, Rx::Dropped(DropReason::Replay));
    }
    assert_eq!(p.b.tunnel.stats().replays_dropped, 64);
}

#[test]
fn counters_far_behind_the_window_are_rejected() {
    use wireguard_sans_io::replay::WINDOW_BITS;
    let mut p = new_pair(22);
    p.establish();
    let early = p.seal_from_a(b"very early");
    // Push the counter far past the window.
    for _ in 0..WINDOW_BITS + 100 {
        let w = p.seal_from_a(b"filler");
        p.open_at_b(&w);
    }
    assert_eq!(
        p.deliver_to_b(&early).rx,
        Rx::Dropped(DropReason::Replay),
        "counter 1 is far below the window and must be dropped"
    );
}

#[test]
fn replayed_initiation_is_rejected_by_timestamp() {
    let mut p = new_pair(23);
    let init = p.a_initiates();
    // First copy: accepted, response produced.
    assert!(matches!(p.deliver_to_b(&init).rx, Rx::Response(_)));
    // Byte-identical replay: timestamp is not strictly greater → rejected,
    // and crucially NO response is generated (whitepaper §5.1: replays
    // must not make the responder regenerate session state).
    assert_eq!(
        p.deliver_to_b(&init).rx,
        Rx::Dropped(DropReason::ReplayedTimestamp)
    );
    // Same one hour later.
    p.clock.advance(3600 * common::S);
    assert_eq!(
        p.deliver_to_b(&init).rx,
        Rx::Dropped(DropReason::ReplayedTimestamp)
    );
    assert_eq!(p.b.tunnel.stats().handshakes_responded, 1);
}

#[test]
fn older_timestamp_rejected_even_if_never_seen() {
    // Two initiations created at t0 and t1 > t0; deliver the newer one
    // first. The older one must then be rejected (monotonicity, not just
    // uniqueness).
    let mut p = new_pair(24);
    let init_old = p.a_initiates();
    // 30s later (well past whitening granularity and pacing).
    p.clock.advance(30 * common::S);
    let init_new = p.a_initiates();
    assert!(matches!(p.deliver_to_b(&init_new).rx, Rx::Response(_)));
    assert_eq!(
        p.deliver_to_b(&init_old).rx,
        Rx::Dropped(DropReason::ReplayedTimestamp)
    );
}

#[test]
fn handshake_response_is_single_use() {
    let mut p = new_pair(25);
    let init = p.a_initiates();
    let resp = match p.deliver_to_b(&init).rx {
        Rx::Response(w) => w,
        other => panic!("{other:?}"),
    };
    assert_eq!(p.deliver_to_a(&resp).rx, Rx::HandshakeComplete);
    // Replaying the response: no in-flight handshake matches any more.
    assert_eq!(
        p.deliver_to_a(&resp).rx,
        Rx::Dropped(DropReason::NoPendingHandshake)
    );
    assert_eq!(p.a.tunnel.stats().handshakes_completed, 1);
}

#[test]
fn response_to_superseded_initiation_is_rejected() {
    // A retransmits (new ephemeral + index); a response to the FIRST
    // initiation must no longer complete. (BoringTun keeps the previous
    // in-flight state and would accept it; this is a behavioural, not a
    // security, difference.)
    let mut p = new_pair(26);
    let init1 = p.a_initiates();
    let resp1 = match p.deliver_to_b(&init1).rx {
        Rx::Response(w) => w,
        other => panic!("{other:?}"),
    };
    // 5+s later the retransmission replaces the in-flight state.
    let later = p.clock.advance(6 * common::S);
    let init2 = match p.a.poll(later, &mut p.rng) {
        common::Polled::Transmit(w, wireguard_sans_io::SendReason::HandshakeRetransmit, _) => w,
        other => panic!("expected a retransmit, got {other:?}"),
    };
    assert_ne!(&init1[4..8], &init2[4..8], "indices must differ");
    assert_eq!(
        p.deliver_to_a(&resp1).rx,
        Rx::Dropped(DropReason::NoPendingHandshake)
    );
}

#[test]
fn unknown_receiver_index_rejected() {
    let mut p = new_pair(27);
    p.establish();
    let wire = p.seal_from_a(b"hello");
    // Every single-bit change of the receiver index is rejected: it either
    // decodes to a peer id that is not B's only tunnel, or to another
    // slot of that tunnel which is not a live session.
    for bit in 0..32 {
        let mut bad = wire.clone();
        bad[4 + bit / 8] ^= 1 << (bit % 8);
        assert_eq!(
            p.deliver_to_b(&bad).rx,
            Rx::Dropped(DropReason::UnknownIndex),
            "bit {bit}"
        );
    }
    assert_eq!(
        p.b.tunnel.stats().auth_failures,
        0,
        "rejected before any AEAD"
    );
    assert_eq!(&p.open_at_b(&wire)[..5], b"hello");
}

#[test]
fn counter_at_reject_after_messages_dropped_before_decryption() {
    let mut p = new_pair(28);
    p.establish();
    let mut wire = p.seal_from_a(b"x");
    // Rewrite the counter field to ≥ REJECT_AFTER_MESSAGES. The AEAD
    // would fail anyway (nonce mismatch), but the counter check must trip
    // first and is the cheap pre-authentication path.
    wire[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(p.deliver_to_b(&wire).rx, Rx::Dropped(DropReason::Expired));
    assert_eq!(p.b.tunnel.stats().auth_failures, 0);
}

/// A valid, fresh initiation that arrives less than 1/50 s after the last
/// accepted one is dropped before a response is built (the kernel's
/// `INITIATIONS_PER_SECOND`), so a peer cannot make us churn sessions.
#[test]
fn initiations_faster_than_fifty_per_second_are_dropped() {
    use wireguard_sans_io::consts::INITIATION_MIN_INTERVAL;
    // Two initiators with the same identity (the peer restarted): both
    // initiations are valid and the second has the later timestamp.
    let mut p = new_pair(29);
    let mut q = new_pair(29); // same keys
    let init1 = p.a_initiates();
    assert!(matches!(p.deliver_to_b(&init1).rx, Rx::Response(_)));

    // 10 ms later a second valid initiation with a newer timestamp.
    p.clock.advance(INITIATION_MIN_INTERVAL / 2);
    q.clock.advance(6 * common::S); // q's own clock: timestamp is newer
    let init2 = q.a_initiates();
    assert_eq!(
        p.deliver_to_b(&init2).rx,
        Rx::Dropped(DropReason::InitiationFlood)
    );
    assert_eq!(p.b.tunnel.stats().handshakes_responded, 1);

    // Dropping it did not record its timestamp: once the interval has
    // passed, the very same initiation is accepted.
    p.clock.advance(INITIATION_MIN_INTERVAL / 2);
    assert!(matches!(p.deliver_to_b(&init2).rx, Rx::Response(_)));
    assert_eq!(p.b.tunnel.stats().handshakes_responded, 2);
}
