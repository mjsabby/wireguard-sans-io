//! The whitepaper §6 timer state machine, exercised by time travel:
//! retransmissions, jitter bounds, attempt expiry, rekeys, reject/expiry,
//! keepalives (passive, confirming, persistent), discard, next_wake.
//!
//! The scenario tests at the end drive both sides only through
//! `next_wake()`/`poll()` (as an embedder does) and, at every step, compare
//! each tunnel's timers with the reference model in
//! `tests/common/timer_model.rs`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;
use common::{
    MS, Opts, Pair, Polled, Rx, S, Sim, Tx, Who, a_addr, b_addr, new_pair, new_pair_opts,
    new_pair_with,
};
use wireguard_sans_io::{
    DropReason, Error, SendReason, Ticks, Timer,
    consts::{
        DEAD_PEER_TIMEOUT, KEEPALIVE_TIMEOUT, REJECT_AFTER_TIME, REKEY_AFTER_TIME,
        REKEY_AFTER_TIME_RECV, REKEY_ATTEMPT_TIME, REKEY_TIMEOUT, REKEY_TIMEOUT_JITTER_MAX,
        SESSION_DISCARD_TIME,
    },
    testing::FailingRng,
};

/// The dead-peer deadline of a tunnel whose first unanswered data packet
/// went out at `sent`: 15 s later, plus the jitter (§6.1: up to a third of
/// a second) the tunnel drew at its last handshake.
#[track_caller]
fn dead_peer_deadline(tunnel: &wireguard_sans_io::Tunnel, sent: Ticks) -> Ticks {
    let deadline = tunnel
        .timer(Timer::NewHandshake)
        .expect("the dead-peer timer is armed");
    let earliest = sent.add_nanos(DEAD_PEER_TIMEOUT);
    assert!(
        deadline >= earliest && deadline <= earliest.add_nanos(REKEY_TIMEOUT_JITTER_MAX),
        "dead-peer deadline {deadline:?} for data sent at {sent:?}"
    );
    deadline
}

#[test]
fn initiation_retransmits_on_schedule_until_attempt_expiry() {
    let mut p = new_pair(40);
    let _ = p.a_initiates();

    let mut sends = 1u32;
    let mut expired = false;
    // Walk poll forward via next_wake until the attempt is abandoned.
    for _ in 0..64 {
        let wake = p.a.tunnel.next_wake().expect("retransmit timer armed");
        assert!(wake.nanos() > p.clock.mono_ns, "wake must be in the future");
        // Strictly before the deadline: nothing happens.
        let just_before = p.clock.advance(wake.nanos() - p.clock.mono_ns - 1);
        assert_eq!(p.a.poll(just_before, &mut p.rng), Polled::Idle);
        let at = p.clock.advance(1);
        match p.a.poll(at, &mut p.rng) {
            Polled::Transmit(w, SendReason::HandshakeRetransmit, dst) => {
                assert_eq!(w.len(), 148);
                assert_eq!(dst, b_addr());
                sends += 1;
            }
            Polled::HandshakeExpired => {
                expired = true;
                break;
            }
            other => panic!("unexpected poll output {other:?}"),
        }
    }
    assert!(expired, "attempt must eventually give up");
    // Spec: retries every REKEY_TIMEOUT (+ ≤333ms jitter) for
    // REKEY_ATTEMPT_TIME (90s): 90/5 ≈ 18 sends, minus jitter slippage.
    assert!(
        (15..=18).contains(&sends),
        "saw {sends} initiation sends, expected ≈17"
    );
    assert!(
        p.clock.mono_ns >= REKEY_ATTEMPT_TIME,
        "gave up before Rekey-Attempt-Time"
    );
    // After giving up the tunnel is quiet: no armed wake-ups.
    let (wires, events) = p.a.drain(p.clock.now(), &mut p.rng);
    assert!(wires.is_empty() && events.is_empty());
    assert_eq!(p.a.tunnel.next_wake(), None, "quiet after abandoning");
    // …until the application sends again, which starts a fresh attempt.
    assert_eq!(p.a.send(p.clock.now(), b"again"), Tx::NoSession);
    assert!(matches!(
        p.a.poll(p.clock.now(), &mut p.rng),
        Polled::Transmit(_, SendReason::HandshakeInitiation, _)
    ));
}

#[test]
fn timer_retransmits_use_distinct_ephemerals_and_indices() {
    // Forward secrecy: every retransmitted initiation must carry a FRESH
    // X25519 ephemeral — reusing one staged ephemeral across retries would
    // erode the per-handshake secrecy guarantee.
    //
    // Wire layout of a HandshakeInitiation: type(4) ‖ sender(4) ‖
    // ephemeral(32), so the unencrypted ephemeral is bytes [8..40].
    let mut p = new_pair(140);
    let init = p.a_initiates();
    let mut ephemerals: Vec<[u8; 32]> = vec![init[8..40].try_into().unwrap()];
    let mut indices: Vec<[u8; 4]> = vec![init[4..8].try_into().unwrap()];

    // Drive several timer-driven retransmits (no response ever arrives).
    for _ in 0..3 {
        let wake = p.a.tunnel.next_wake().expect("retransmit timer armed");
        let at = p.clock.set(wake);
        match p.a.poll(at, &mut p.rng) {
            Polled::Transmit(w, SendReason::HandshakeRetransmit, _) => {
                assert_eq!(w.len(), 148);
                ephemerals.push(w[8..40].try_into().unwrap());
                indices.push(w[4..8].try_into().unwrap());
            }
            other => panic!("expected a retransmit, got {other:?}"),
        }
    }

    // All four (initial + 3 retransmits) must be pairwise distinct.
    for i in 0..ephemerals.len() {
        for j in (i + 1)..ephemerals.len() {
            assert_ne!(
                ephemerals[i], ephemerals[j],
                "ephemeral reused ({i} == {j})"
            );
            assert_ne!(indices[i], indices[j], "index reused ({i} == {j})");
        }
    }
}

#[test]
fn new_initiation_does_not_extend_current_session_expiry() {
    // A fresh initiation arriving mid-session must NOT reset the *current*
    // session's Reject-After-Time clock: the live session has to die at its
    // own birthdate + 180s regardless of later handshake traffic.
    let mut p = new_pair(141);
    p.establish(); // current = v1 on both, born at t = 0.

    // Seal two v1 transport packets before anything else perturbs state.
    p.clock.advance(99 * S);
    let v1_early = p.seal_from_a(b"v1 early");
    let v1_late = p.seal_from_a(b"v1 late!");

    // At t = 100s a brand-new initiation from A arrives at B (an
    // unsolicited rekey). B installs it as a pending `next` session and
    // responds; v1 stays `current` with its original birthdate.
    p.clock.advance(S);
    let init = p.a_initiates();
    assert!(matches!(p.deliver_to_b(&init).rx, Rx::Response(_)));

    // Control: at t = 179s (< birthdate + 180s) v1 is still alive.
    p.clock.advance(79 * S);
    assert_eq!(&p.open_at_b(&v1_early)[..8], b"v1 early");

    // The invariant: at t = 181s v1 is past birthdate + 180s and MUST be
    // rejected as Expired.
    p.clock.advance(2 * S);
    assert_eq!(
        p.deliver_to_b(&v1_late).rx,
        Rx::Dropped(DropReason::Expired)
    );
}

#[test]
fn retransmission_jitter_is_within_spec_bounds() {
    // Across many handshake attempts, the gap between sends must be in
    // [REKEY_TIMEOUT, REKEY_TIMEOUT + 333ms] and must actually vary.
    let mut p = new_pair(41);
    let _ = p.a_initiates();
    let mut last_send = p.clock.mono_ns;
    let mut gaps = Vec::new();
    for _ in 0..10 {
        let wake = p.a.tunnel.next_wake().unwrap();
        let at = p.clock.set(wake);
        match p.a.poll(at, &mut p.rng) {
            Polled::Transmit(_, SendReason::HandshakeRetransmit, _) => {
                gaps.push(p.clock.mono_ns - last_send);
                last_send = p.clock.mono_ns;
            }
            Polled::HandshakeExpired => break,
            other => panic!("{other:?}"),
        }
    }
    assert!(gaps.len() >= 8);
    for gap in &gaps {
        assert!(*gap >= REKEY_TIMEOUT, "gap {gap} below Rekey-Timeout");
        assert!(
            *gap <= REKEY_TIMEOUT + REKEY_TIMEOUT_JITTER_MAX,
            "gap {gap} beyond jitter bound"
        );
    }
    assert!(
        gaps.iter().collect::<std::collections::HashSet<_>>().len() > 1,
        "jitter must vary: {gaps:?}"
    );
}

/// §6.1: "Under no circumstances will WireGuard send an initiation message
/// more than once every Rekey-Timeout."
#[test]
fn initiation_pacing_is_global() {
    let mut p = new_pair(42);
    let _ = p.a_initiates();
    // A second request while that handshake is in flight is absorbed: the
    // retransmit timer is what sends the next initiation.
    let soon = p.clock.advance(REKEY_TIMEOUT - 1);
    p.a.tunnel.request_handshake(soon);
    assert_eq!(p.a.poll(soon, &mut p.rng), Polled::Idle);
    assert!(p.a.tunnel.timer(Timer::SendInitiation).is_none());

    // Pacing survives reset(): the in-flight handshake is gone, a new one
    // is wanted, but it is not sent before Rekey-Timeout has passed since
    // the last initiation.
    p.a.tunnel.reset();
    p.a.tunnel.request_handshake(soon);
    assert_eq!(p.a.poll(soon, &mut p.rng), Polled::Idle);
    assert_eq!(
        p.a.tunnel.next_wake(),
        Some(Ticks::from_nanos(REKEY_TIMEOUT)),
        "the request waits for exactly the pacing deadline"
    );
    let ok_at = p.clock.advance(1);
    assert!(matches!(
        p.a.poll(ok_at, &mut p.rng),
        Polled::Transmit(_, SendReason::HandshakeInitiation, _)
    ));
    assert_eq!(p.a.tunnel.stats().handshakes_initiated, 2);
}

/// Answering the peer's initiation counts as a handshake message sent: our
/// own initiation waits Rekey-Timeout after it (as in the kernel, where
/// both set `last_sent_handshake`). Without this, two peers that both want
/// a session trade redundant handshakes.
#[test]
fn responding_paces_our_own_initiation() {
    let mut p = new_pair(142);
    let now = p.clock.now();
    let init = p.a_initiates();
    assert!(matches!(p.deliver_to_b(&init).rx, Rx::Response(_)));
    // B now wants to send, has only an unconfirmed session, and so wants
    // a handshake of its own — but not within 5 s of its response.
    assert_eq!(p.b.send(now, b"x"), Tx::NoSession);
    assert_eq!(p.b.poll(now, &mut p.rng), Polled::Idle);
    assert_eq!(
        p.b.tunnel.timer(Timer::SendInitiation),
        Some(Ticks::from_nanos(REKEY_TIMEOUT))
    );
    let later = p.clock.advance(REKEY_TIMEOUT);
    assert!(matches!(
        p.b.poll(later, &mut p.rng),
        Polled::Transmit(_, SendReason::HandshakeInitiation, _)
    ));
}

#[test]
fn rekey_after_time_via_send_path() {
    let mut p = new_pair(43);
    p.establish();
    // Just before REKEY_AFTER_TIME: sending does not trigger a rekey.
    p.clock.advance(REKEY_AFTER_TIME - S);
    p.assert_roundtrip_a_to_b(b"young session");
    let (wires, _) = p.a.drain(p.clock.now(), &mut p.rng);
    assert!(wires.is_empty(), "no rekey yet: {wires:?}");
    // Cross the threshold: the next send requests a rekey and poll emits a
    // fresh initiation (the initiator-only rule).
    p.clock.advance(2 * S);
    p.assert_roundtrip_a_to_b(b"aging session");
    let (wires, _) = p.a.drain(p.clock.now(), &mut p.rng);
    assert_eq!(wires.len(), 1, "exactly one initiation");
    assert_eq!(wires[0].1, SendReason::HandshakeInitiation);
    assert_eq!(wires[0].0[0], 1);
    // The responder does NOT rekey on time (thundering-herd prevention).
    let wire = p.seal_from_b(b"responder traffic");
    let _ = p.open_at_a(&wire);
    let (wires, _) = p.b.drain(p.clock.now(), &mut p.rng);
    assert!(wires.is_empty(), "responder must not time-rekey: {wires:?}");
}

#[test]
fn rekey_on_receive_path_when_reject_approaches() {
    let mut p = new_pair(44);
    p.establish();
    // A (initiator) hears from B after 165s (= Reject − Keepalive −
    // Rekey): receive path must trigger A's rekey, once.
    p.clock.advance(REKEY_AFTER_TIME_RECV);
    let wire = p.seal_from_b(b"still here");
    let _ = p.open_at_a(&wire);
    let (wires, _) = p.a.drain(p.clock.now(), &mut p.rng);
    assert_eq!(wires.len(), 1);
    assert_eq!(wires[0].1, SendReason::HandshakeInitiation);
    // Receiving more data does not double-trigger ("has not yet acted
    // upon this event" is latched).
    let wire = p.seal_from_b(b"more");
    let _ = p.open_at_a(&wire);
    let (wires, _) = p.a.drain(p.clock.now(), &mut p.rng);
    assert!(wires.is_empty(), "no second fresh initiation: {wires:?}");
    assert_eq!(p.a.tunnel.stats().handshakes_initiated, 2);
}

/// The latch belongs to one session: the next session's last minute
/// triggers a rekey of its own.
#[test]
fn every_session_gets_its_own_last_minute_rekey() {
    let mut p = new_pair(144);
    p.establish();
    for round in 0..3 {
        p.clock.advance(REKEY_AFTER_TIME_RECV);
        let wire = p.seal_from_b(b"still here");
        let _ = p.open_at_a(&wire);
        let (wires, _) = p.a.drain(p.clock.now(), &mut p.rng);
        assert_eq!(wires.len(), 1, "round {round}: {wires:?}");
        assert_eq!(wires[0].1, SendReason::HandshakeInitiation);
        // The rekey completes: a new session, A its initiator again.
        let Rx::Response(response) = p.deliver_to_b(&wires[0].0).rx else {
            panic!("round {round}: B did not answer")
        };
        assert_eq!(p.deliver_to_a(&response).rx, Rx::HandshakeComplete);
        let (wires, _) = p.a.drain(p.clock.now(), &mut p.rng);
        assert_eq!(wires.len(), 1, "the confirming keepalive");
        assert_eq!(p.deliver_to_b(&wires[0].0).rx, Rx::Keepalive);
        assert!(p.b.drain(p.clock.now(), &mut p.rng).0.is_empty());
    }
    assert_eq!(p.a.tunnel.stats().handshakes_initiated, 4);
}

/// Only the initiator of a session rekeys it on a timer — on the receive
/// path as on the send path. If both sides did, every session would end
/// in two handshakes started at the same moment.
#[test]
fn the_responder_does_not_rekey_on_the_receive_path() {
    let mut p = new_pair(145);
    p.establish();
    p.clock.advance(REKEY_AFTER_TIME_RECV);
    // B, the responder, hears from A in the session's last minute.
    let wire = p.seal_from_a(b"still here");
    let _ = p.open_at_b(&wire);
    let (wires, events) = p.b.drain(p.clock.now(), &mut p.rng);
    assert!(wires.is_empty() && events.is_empty(), "{wires:?}");
    assert_eq!(p.b.tunnel.stats().handshakes_initiated, 0);
    // …and right up to the session's end.
    p.clock
        .advance(REJECT_AFTER_TIME - REKEY_AFTER_TIME_RECV - 1);
    let wire = p.seal_from_a(b"last moment");
    let _ = p.open_at_b(&wire);
    // (The keepalive B owes A is all that B has to send.)
    assert_eq!(p.b.tunnel.timer(Timer::SendInitiation), None);
    assert_eq!(p.b.tunnel.stats().handshakes_initiated, 0);
}

/// A handshake that is wanted but has nowhere to go starts as soon as
/// the endpoint is set.
#[test]
fn a_waiting_handshake_starts_when_the_endpoint_becomes_known() {
    let mut p = new_pair_opts(
        146,
        Opts {
            b_without_endpoint: true,
            ..Opts::default()
        },
    );
    let now = p.clock.advance(S);
    assert_eq!(p.b.send(now, b"x"), Tx::NoEndpoint);
    assert_eq!(p.b.poll(now, &mut p.rng), Polled::Idle);
    assert_eq!(p.b.tunnel.next_wake(), None, "nothing to wait for yet");

    p.b.tunnel.set_endpoint(a_addr());
    assert_eq!(
        p.b.tunnel.next_wake(),
        Some(now),
        "the handshake that was waiting is due at once"
    );
    match p.b.poll(now, &mut p.rng) {
        Polled::Transmit(w, SendReason::HandshakeInitiation, dst) => {
            assert_eq!(dst, a_addr());
            assert_eq!(w[0], 1);
        }
        other => panic!("{other:?}"),
    }
    // Without a handshake wanted, setting the endpoint starts nothing.
    let mut q = new_pair_opts(
        147,
        Opts {
            b_without_endpoint: true,
            ..Opts::default()
        },
    );
    q.b.tunnel.set_endpoint(a_addr());
    assert_eq!(q.b.tunnel.next_wake(), None);
    assert_eq!(q.b.poll(Ticks::from_secs(1), &mut q.rng), Polled::Idle);
}

#[test]
fn reject_after_time_blocks_both_directions() {
    let mut p = new_pair(45);
    p.establish();
    let wire_before = p.seal_from_a(b"sent in time");
    p.clock.advance(REJECT_AFTER_TIME);
    // Sending: the expired session is unusable; nothing is encrypted and a
    // new handshake is requested.
    let now = p.clock.now();
    assert!(!p.a.is_established(now));
    assert_eq!(p.a.send(now, b"too late"), Tx::NoSession);
    // Receiving: a datagram encrypted in time but delivered after the
    // deadline is rejected.
    assert_eq!(
        p.deliver_to_b(&wire_before).rx,
        Rx::Dropped(DropReason::Expired)
    );
}

#[test]
fn passive_keepalive_emitted_once_after_quiet_receive() {
    let mut p = new_pair(46);
    p.establish();
    // B receives data and never answers.
    let wire = p.seal_from_a(b"talk to me");
    let _ = p.open_at_b(&wire);
    // Just before Keepalive-Timeout: nothing.
    p.clock.advance(KEEPALIVE_TIMEOUT - 1);
    assert_eq!(p.b.poll(p.clock.now(), &mut p.rng), Polled::Idle);
    // At the deadline: exactly one keepalive.
    p.clock.advance(1);
    let (wires, _) = p.b.drain(p.clock.now(), &mut p.rng);
    assert_eq!(wires.len(), 1);
    assert_eq!(wires[0].1, SendReason::Keepalive);
    assert_eq!(wires[0].0.len(), 32);
    // A accepts it as a keepalive (not data).
    assert_eq!(p.deliver_to_a(&wires[0].0).rx, Rx::Keepalive);
    // No repeat keepalive without new inbound data.
    p.clock.advance(KEEPALIVE_TIMEOUT * 3);
    let (wires, _) = p.b.drain(p.clock.now(), &mut p.rng);
    assert!(wires.is_empty(), "{wires:?}");
}

/// §6.5: the keepalive is due Keepalive-Timeout after the FIRST data
/// packet we have not answered — later packets do not push it back.
#[test]
fn passive_keepalive_counts_from_the_first_unanswered_packet() {
    let mut p = new_pair(146);
    p.establish();
    // Data arrives at t = 0, 3, 6, 9 s.
    for _ in 0..4 {
        let wire = p.seal_from_a(b"stream");
        let _ = p.open_at_b(&wire);
        p.clock.advance(3 * S);
    }
    assert_eq!(
        p.b.tunnel.timer(Timer::SendKeepalive),
        Some(Ticks::from_nanos(KEEPALIVE_TIMEOUT)),
        "deadline is first packet + 10 s, not last packet + 10 s"
    );
    // t = 12 s: already due.
    let (wires, _) = p.b.drain(p.clock.now(), &mut p.rng);
    assert_eq!(wires.len(), 1);
    assert_eq!(wires[0].1, SendReason::Keepalive);
    // Anything we send ourselves answers the peer: the timer is cancelled.
    let wire = p.seal_from_a(b"more");
    let _ = p.open_at_b(&wire);
    assert!(p.b.tunnel.timer(Timer::SendKeepalive).is_some());
    let _ = p.seal_from_b(b"reply");
    assert_eq!(p.b.tunnel.timer(Timer::SendKeepalive), None);
}

#[test]
fn keepalives_do_not_arm_passive_keepalive() {
    let mut p = new_pair(47);
    p.establish();
    // B receives only a keepalive (not data): it owes no reply.
    let ka = p.seal_from_a(b"");
    assert_eq!(p.deliver_to_b(&ka).rx, Rx::Keepalive);
    p.clock.advance(KEEPALIVE_TIMEOUT * 2);
    let (wires, _) = p.b.drain(p.clock.now(), &mut p.rng);
    assert!(wires.is_empty(), "keepalive ping-pong loop: {wires:?}");
}

#[test]
fn dead_peer_triggers_new_handshake() {
    let mut p = new_pair(48);
    p.establish();
    // A sends data; B never receives it (network ate it). After
    // Keepalive-Timeout + Rekey-Timeout, A must start a new handshake.
    let sent = p.clock.now();
    let _lost = p.seal_from_a(b"into the void");
    let due = dead_peer_deadline(&p.a.tunnel, sent);
    p.clock.set(Ticks::from_nanos(due.nanos() - 1));
    assert_eq!(p.a.poll(p.clock.now(), &mut p.rng), Polled::Idle);
    p.clock.advance(1);
    let (wires, _) = p.a.drain(p.clock.now(), &mut p.rng);
    assert_eq!(wires.len(), 1);
    assert_eq!(wires[0].1, SendReason::HandshakeInitiation);
    // A reply in time would have prevented it.
    let mut q = new_pair(49);
    q.establish();
    let wire = q.seal_from_a(b"hello?");
    let got = q.open_at_b(&wire);
    assert_eq!(&got[..6], b"hello?");
    let reply = q.seal_from_b(b"here!");
    let _ = q.open_at_a(&reply);
    q.clock.advance(DEAD_PEER_TIMEOUT + S);
    let (wires, _) = q.a.drain(q.clock.now(), &mut q.rng);
    // No new handshake. (A does owe B a keepalive: it received data and
    // has sent nothing since.)
    assert_eq!(wires.len(), 1, "{wires:?}");
    assert_eq!(wires[0].1, SendReason::Keepalive);
    assert_eq!(q.a.tunnel.stats().handshakes_initiated, 1);
}

/// §6.1: the timer that starts a handshake when the peer has gone quiet
/// is jittered by up to a third of a second, as in the kernel
/// (`wg_timers_data_sent`). Without it, two ends that stop hearing each
/// other at the same instant — a path that drops for a moment under
/// two-way traffic — both start their handshakes 15.000 s later, to the
/// nanosecond, and the two initiations cross every time.
#[test]
fn the_dead_peer_timer_is_jittered() {
    let mut jitters_a = Vec::new();
    let mut jitters_b = Vec::new();
    let mut apart = 0;
    for seed in 0..64u64 {
        let mut p = new_pair(0x1000 + seed);
        p.clock.advance(seed * 7 * MS);
        p.establish();
        // Both ends send at the same instant; neither hears the other.
        let sent = p.clock.advance(3 * S);
        let _lost = p.seal_from_a(b"a to b");
        let _lost = p.seal_from_b(b"b to a");
        let a = dead_peer_deadline(&p.a.tunnel, sent).since(sent) - DEAD_PEER_TIMEOUT;
        let b = dead_peer_deadline(&p.b.tunnel, sent).since(sent) - DEAD_PEER_TIMEOUT;
        jitters_a.push(a);
        jitters_b.push(b);
        // A millisecond is more than the lead a handshake needs on a LAN.
        apart += usize::from(a.abs_diff(b) > MS);
    }
    for (who, jitters) in [("initiator", &jitters_a), ("responder", &jitters_b)] {
        let (min, max) = (jitters.iter().min().unwrap(), jitters.iter().max().unwrap());
        // Uniform over 0..=333 ms: 64 draws reach into both ends.
        assert!(*min < 40 * MS, "{who}: smallest jitter {min}");
        assert!(*max > 290 * MS, "{who}: largest jitter {max}");
        assert!(*max <= REKEY_TIMEOUT_JITTER_MAX, "{who}: {max}");
        let distinct: std::collections::HashSet<_> = jitters.iter().collect();
        assert_eq!(distinct.len(), jitters.len(), "{who}: a jitter repeated");
    }
    assert!(
        apart >= 62,
        "the two ends' deadlines were apart in {apart} of 64 runs"
    );

    // The jitter belongs to the session: every arming until the next
    // handshake uses it, and the next handshake draws another.
    let mut p = new_pair(0x1100);
    p.establish();
    let mut seen = std::collections::HashSet::new();
    for round in 0..4u64 {
        let mut this_session = None;
        for _ in 0..3 {
            let sent = p.clock.advance(S);
            let _lost = p.seal_from_a(b"unanswered");
            let jitter = dead_peer_deadline(&p.a.tunnel, sent).since(sent) - DEAD_PEER_TIMEOUT;
            assert_eq!(*this_session.get_or_insert(jitter), jitter, "round {round}");
            // The peer is heard from: the timer is cancelled.
            let ka = p.seal_from_b(b"");
            assert_eq!(p.deliver_to_a(&ka).rx, Rx::Keepalive);
        }
        assert!(seen.insert(this_session.unwrap()), "round {round}");
        // A new handshake, from the other side this time round.
        p.clock.advance(6 * S);
        let init = if round % 2 == 0 {
            p.b_initiates()
        } else {
            p.a_initiates()
        };
        let (first, second) = if round % 2 == 0 {
            (&mut p.a, &mut p.b)
        } else {
            (&mut p.b, &mut p.a)
        };
        let now = p.clock.now();
        let resp = match first
            .recv_from(now, second.addr, false, &init, &mut p.rng)
            .rx
        {
            Rx::Response(w) => w,
            other => panic!("{other:?}"),
        };
        let done = second.recv_from(now, first.addr, false, &resp, &mut p.rng);
        assert_eq!(done.rx, Rx::HandshakeComplete);
        for (wire, _) in second.drain(now, &mut p.rng).0 {
            let _ = first.recv_from(now, second.addr, false, &wire, &mut p.rng);
        }
    }
}

/// §6.5: the dead-peer deadline counts from the FIRST data packet that
/// has not been answered — later sends do not push it back.
#[test]
fn dead_peer_deadline_counts_from_the_first_unanswered_packet() {
    let mut p = new_pair(148);
    p.establish();
    let first = p.clock.now();
    let mut deadline = None;
    for _ in 0..5 {
        let _lost = p.seal_from_a(b"stream into the void");
        // The deadline is the first packet's — 15 s after it, plus this
        // session's jitter — and later sends leave it where it is.
        let now = dead_peer_deadline(&p.a.tunnel, first);
        assert_eq!(*deadline.get_or_insert(now), now);
        p.clock.advance(2 * S);
    }
    // Any authenticated message from the peer — here a bare keepalive —
    // cancels it.
    let ka = p.seal_from_b(b"");
    assert_eq!(p.deliver_to_a(&ka).rx, Rx::Keepalive);
    assert_eq!(p.a.tunnel.timer(Timer::NewHandshake), None);
}

/// A valid handshake message is "hearing from the peer" too (the kernel's
/// `wg_timers_any_authenticated_packet_received` runs for handshake
/// packets): it cancels the dead-peer timer.
#[test]
fn handshake_messages_cancel_the_dead_peer_timer() {
    // (a) the peer's initiation.
    let mut p = new_pair(149);
    p.establish();
    let _lost = p.seal_from_a(b"lost");
    assert!(p.a.tunnel.timer(Timer::NewHandshake).is_some());
    p.clock.advance(6 * S);
    let init = p.b_initiates();
    assert!(matches!(p.deliver_to_a(&init).rx, Rx::Response(_)));
    assert_eq!(p.a.tunnel.timer(Timer::NewHandshake), None);

    // (b) the peer's response to our initiation.
    let mut p = new_pair(150);
    p.establish();
    let _lost = p.seal_from_a(b"lost");
    p.clock.advance(6 * S);
    let init = p.a_initiates();
    let resp = match p.deliver_to_b(&init).rx {
        Rx::Response(w) => w,
        other => panic!("{other:?}"),
    };
    assert!(p.a.tunnel.timer(Timer::NewHandshake).is_some());
    assert_eq!(p.deliver_to_a(&resp).rx, Rx::HandshakeComplete);
    assert_eq!(p.a.tunnel.timer(Timer::NewHandshake), None);
}

#[test]
fn session_discard_after_three_reject_after_time() {
    let mut p = new_pair(50);
    p.establish();
    p.clock.advance(SESSION_DISCARD_TIME - 1);
    assert_eq!(p.a.poll(p.clock.now(), &mut p.rng), Polled::Idle);
    // At 540 s − 1 ns the current session is long past Reject-After-Time
    // and no longer usable for sending, even though the slot has not yet
    // been wiped.
    assert!(!p.a.is_established(p.clock.now()));
    assert!(p.a.tunnel.stats().last_handshake_at.is_some());
    p.clock.advance(1);
    let (_, events) = p.a.drain(p.clock.now(), &mut p.rng);
    assert_eq!(events, vec!["sessions_expired"]);
    assert!(!p.a.is_established(p.clock.now()));
    assert_eq!(p.a.tunnel.next_wake(), None, "fully quiet after discard");
    // The responder's keys are wiped on the same schedule.
    let (_, events) = p.b.drain(p.clock.now(), &mut p.rng);
    assert_eq!(events, vec!["sessions_expired"]);
    // The tunnel still works: a fresh handshake re-establishes.
    p.establish();
    p.assert_roundtrip_a_to_b(b"back again");
}

/// An unconfirmed responder session must not push the wipe of the
/// established sessions past `current.created + 540 s`.
#[test]
fn unconfirmed_next_does_not_delay_session_discard() {
    let mut p = new_pair(0xb00d);
    p.establish(); // current born at t = 0 on both sides.

    // At t = 300 s, B (acting as initiator) sends an initiation that A
    // answers — installing an unconfirmed `next` in A — but B never
    // confirms (the response is dropped).
    p.clock.advance(300 * S);
    let init = p.b_initiates();
    assert!(matches!(p.deliver_to_a(&init).rx, Rx::Response(_)));
    assert_eq!(
        p.a.tunnel.timer(Timer::ExpireNextSession),
        Some(Ticks::from_nanos(300 * S + REJECT_AFTER_TIME))
    );
    assert_eq!(
        p.a.tunnel.timer(Timer::ZeroKeyMaterial),
        Some(Ticks::from_nanos(SESSION_DISCARD_TIME)),
        "an unconfirmed session does not move the wipe deadline"
    );

    // Drive A purely by next_wake: the unconfirmed session is dropped at
    // 480 s, and everything is wiped at exactly 540 s.
    let mut wiped_at = None;
    for _ in 0..50 {
        let Some(wake) = p.a.tunnel.next_wake() else {
            break;
        };
        let now = p.clock.set(wake);
        let (_, events) = p.a.drain(now, &mut p.rng);
        if events.contains(&"sessions_expired") {
            wiped_at = Some(p.clock.mono_ns);
            break;
        }
    }
    assert_eq!(wiped_at, Some(SESSION_DISCARD_TIME));
}

/// The key-wipe timer is about keys that have gone stale. A handshake of
/// ours that is under way when it fires is left alone: the response that
/// is on its way still completes it.
#[test]
fn key_wipe_spares_an_initiation_in_flight() {
    let mut p = new_pair(151);
    p.establish();
    // 2 s before the wipe the application sends: the session is long past
    // Reject-After-Time, so a handshake starts.
    p.clock.advance(SESSION_DISCARD_TIME - 2 * S);
    assert_eq!(p.a.send(p.clock.now(), b"x"), Tx::NoSession);
    let init = match p.a.poll(p.clock.now(), &mut p.rng) {
        Polled::Transmit(w, SendReason::HandshakeInitiation, _) => w,
        other => panic!("{other:?}"),
    };
    let retransmit_at = p.a.tunnel.timer(Timer::RetransmitHandshake);
    let Rx::Response(resp) = p.deliver_to_b(&init).rx else {
        panic!("B did not answer")
    };
    // A's wipe fires at 540 s, while the response is still on its way…
    p.clock.advance(2 * S);
    let (wires, events) = p.a.drain(p.clock.now(), &mut p.rng);
    assert_eq!(events, vec!["sessions_expired"]);
    assert!(wires.is_empty());
    assert_eq!(
        p.a.tunnel.timer(Timer::RetransmitHandshake),
        retransmit_at,
        "the attempt goes on as it was"
    );
    assert_eq!(p.a.tunnel.timer(Timer::ZeroKeyMaterial), None);
    // …and the response completes the handshake when it arrives.
    p.clock.advance(100 * MS);
    let info = p.deliver_to_a(&resp);
    assert_eq!(info.rx, Rx::HandshakeComplete);
    assert!(info.session_established);
    p.assert_roundtrip_a_to_b(b"sent on the new session");
    // The new session has its own wipe deadline.
    assert_eq!(
        p.a.tunnel.timer(Timer::ZeroKeyMaterial),
        Some(p.clock.now().add_nanos(SESSION_DISCARD_TIME))
    );
}

/// The same toward a peer that does not answer: the attempt is neither
/// restarted nor forgotten by the wipe. It retransmits on its own timer
/// and ends, as every attempt does, with `HandshakeExpired`.
#[test]
fn key_wipe_does_not_abandon_a_running_handshake() {
    let mut p = new_pair(153);
    p.establish();
    p.clock.advance(SESSION_DISCARD_TIME - 2 * S);
    assert_eq!(p.a.send(p.clock.now(), b"x"), Tx::NoSession);
    assert!(matches!(
        p.a.poll(p.clock.now(), &mut p.rng),
        Polled::Transmit(_, SendReason::HandshakeInitiation, _)
    ));
    let retransmit_at =
        p.a.tunnel
            .timer(Timer::RetransmitHandshake)
            .expect("an attempt is running");
    p.clock.advance(2 * S);
    let (wires, events) = p.a.drain(p.clock.now(), &mut p.rng);
    assert_eq!(events, vec!["sessions_expired"]);
    assert!(wires.is_empty());
    // The next thing the tunnel does is the retransmission, when it was
    // due anyway.
    assert_eq!(p.a.tunnel.next_wake(), Some(retransmit_at));
    let (wires, _) = p.a.drain(p.clock.set(retransmit_at), &mut p.rng);
    assert_eq!(wires.len(), 1);
    assert_eq!(wires[0].1, SendReason::HandshakeRetransmit);
    let mut gave_up = false;
    for _ in 0..40 {
        let Some(wake) = p.a.tunnel.next_wake() else {
            break;
        };
        let (_, events) = p.a.drain(p.clock.set(wake), &mut p.rng);
        if events.contains(&"handshake_expired") {
            gave_up = true;
            break;
        }
    }
    assert!(gave_up, "the embedder must be told to drop its queue");
}

/// What a retransmission needs survives the wipe with the initiation: a
/// cookie the peer handed out is still presented, and a cookie reply that
/// arrives afterwards is still understood.
#[test]
fn key_wipe_leaves_the_cookie_of_a_running_handshake() {
    let mut p = new_pair(154);
    p.establish();
    p.clock.advance(SESSION_DISCARD_TIME - 2 * S);
    assert_eq!(p.a.send(p.clock.now(), b"x"), Tx::NoSession);
    let init = match p.a.poll(p.clock.now(), &mut p.rng) {
        Polled::Transmit(w, SendReason::HandshakeInitiation, _) => w,
        other => panic!("{other:?}"),
    };
    // B is under load and answers with a cookie, which arrives after A's
    // wipe timer has fired.
    let now = p.clock.now();
    let Rx::CookieReply(cookie) = p.b.recv_from(now, p.a.addr, true, &init, &mut p.rng).rx else {
        panic!("B is under load: expected a cookie reply")
    };
    p.clock.advance(2 * S);
    let (_, events) = p.a.drain(p.clock.now(), &mut p.rng);
    assert_eq!(events, vec!["sessions_expired"]);
    assert_eq!(p.deliver_to_a(&cookie).rx, Rx::CookieStored);

    // A second wipe cannot happen (the timer is not armed), so check the
    // other half on a fresh pair: a cookie received before the wipe.
    let mut p = new_pair(155);
    p.establish();
    p.clock.advance(SESSION_DISCARD_TIME - 2 * S);
    assert_eq!(p.a.send(p.clock.now(), b"x"), Tx::NoSession);
    let init = match p.a.poll(p.clock.now(), &mut p.rng) {
        Polled::Transmit(w, SendReason::HandshakeInitiation, _) => w,
        other => panic!("{other:?}"),
    };
    let now = p.clock.now();
    let Rx::CookieReply(cookie) = p.b.recv_from(now, p.a.addr, true, &init, &mut p.rng).rx else {
        panic!("B is under load: expected a cookie reply")
    };
    assert_eq!(p.deliver_to_a(&cookie).rx, Rx::CookieStored);
    p.clock.advance(2 * S);
    let (_, events) = p.a.drain(p.clock.now(), &mut p.rng);
    assert_eq!(events, vec!["sessions_expired"]);
    // The retransmission presents the cookie: B, still under load, answers
    // it with a response instead of another cookie.
    let wake = p.a.tunnel.next_wake().expect("the attempt is running");
    let (wires, _) = p.a.drain(p.clock.set(wake), &mut p.rng);
    assert_eq!(wires.len(), 1);
    let now = p.clock.now();
    let info = p.b.recv_from(now, p.a.addr, true, &wires[0].0, &mut p.rng);
    assert!(matches!(info.rx, Rx::Response(_)), "{info:?}");
}

/// The key-wipe timer of an old session must not destroy a session the
/// peer has just initiated and we have just answered: the peer may
/// already hold our response, and would talk to nobody for the fifteen
/// seconds its dead-peer timer takes.
#[test]
fn key_wipe_spares_a_session_answered_moments_before() {
    let mut p = new_pair(152);
    p.establish();
    // A's initiation reaches B 30 ms before B's wipe deadline.
    p.clock.advance(SESSION_DISCARD_TIME - 30 * MS);
    assert_eq!(p.a.send(p.clock.now(), b"x"), Tx::NoSession);
    let init = match p.a.poll(p.clock.now(), &mut p.rng) {
        Polled::Transmit(w, SendReason::HandshakeInitiation, _) => w,
        other => panic!("{other:?}"),
    };
    let Rx::Response(resp) = p.deliver_to_b(&init).rx else {
        panic!("B did not answer")
    };
    let answered_at = p.clock.now();
    assert_eq!(p.b.poll(p.clock.now(), &mut p.rng), Polled::Idle);
    // B's wipe timer fires while the response is on its way to A.
    p.clock.advance(30 * MS);
    let (wires, events) = p.b.drain(p.clock.now(), &mut p.rng);
    assert_eq!(events, vec!["sessions_expired"]);
    assert!(wires.is_empty());
    // The session B answered with lives on, until its own deadline.
    assert_eq!(
        p.b.tunnel.next_wake(),
        Some(answered_at.add_nanos(REJECT_AFTER_TIME))
    );

    // A completes the handshake and sends: B accepts it at once.
    p.clock.advance(10 * MS);
    let info = p.deliver_to_a(&resp);
    assert_eq!(info.rx, Rx::HandshakeComplete);
    let wire = p.seal_from_a(b"first packet on the new session");
    let info = p.deliver_to_b(&wire);
    assert!(matches!(info.rx, Rx::Data(_)), "{info:?}");
    assert!(info.session_established);
    let wire = p.seal_from_b(b"and back");
    assert!(matches!(p.deliver_to_a(&wire).rx, Rx::Data(_)));
    // The wipe deadline now belongs to the new session.
    assert_eq!(
        p.b.tunnel.timer(Timer::ZeroKeyMaterial),
        Some(answered_at.add_nanos(SESSION_DISCARD_TIME))
    );
}

/// A session that survived the key wipe because the peer's handshake was
/// under way is still wiped, Reject-After-Time after we answered, if the
/// peer never uses it — and a session the peer *has* used is not spared.
#[test]
fn key_wipe_spares_only_a_pending_session_and_only_until_it_expires() {
    let mut p = new_pair(156);
    p.establish();
    p.clock.advance(SESSION_DISCARD_TIME - 30 * MS);
    assert_eq!(p.a.send(p.clock.now(), b"x"), Tx::NoSession);
    let init = match p.a.poll(p.clock.now(), &mut p.rng) {
        Polled::Transmit(w, SendReason::HandshakeInitiation, _) => w,
        other => panic!("{other:?}"),
    };
    let Rx::Response(resp) = p.deliver_to_b(&init).rx else {
        panic!("B did not answer")
    };
    let answered_at = p.clock.now();
    p.clock.advance(30 * MS);
    let (_, events) = p.b.drain(p.clock.now(), &mut p.rng);
    assert_eq!(events, vec!["sessions_expired"]);
    // A completes, but nothing it sends reaches B for three minutes.
    assert_eq!(p.deliver_to_a(&resp).rx, Rx::HandshakeComplete);
    let late = p.seal_from_a(b"held up for three minutes");
    // One nanosecond before the session's deadline B has nothing to do…
    p.clock.set(answered_at.add_nanos(REJECT_AFTER_TIME - 1));
    assert_eq!(p.b.poll(p.clock.now(), &mut p.rng), Polled::Idle);
    // …and at the deadline the session goes, silently (it was never in
    // use, so there is nothing to report).
    p.clock.set(answered_at.add_nanos(REJECT_AFTER_TIME));
    let (wires, events) = p.b.drain(p.clock.now(), &mut p.rng);
    assert!(wires.is_empty() && events.is_empty());
    assert_eq!(p.b.tunnel.next_wake(), None, "B has no state left");
    assert_eq!(
        p.deliver_to_b(&late).rx,
        Rx::Dropped(DropReason::UnknownIndex),
        "the session is gone, not merely too old"
    );
}

#[test]
fn persistent_keepalive_keeps_link_warm() {
    let mut p = new_pair_with(51, None, Some(25));
    p.establish();
    // Quiet link: at 25s the persistent keepalive fires.
    p.clock.advance(25 * S - 1);
    assert_eq!(p.a.poll(p.clock.now(), &mut p.rng), Polled::Idle);
    p.clock.advance(1);
    let (wires, _) = p.a.drain(p.clock.now(), &mut p.rng);
    assert_eq!(wires.len(), 1);
    assert_eq!(wires[0].1, SendReason::PersistentKeepalive);
    // Deliver to B so its counters move; then repeat period works too.
    assert_eq!(p.deliver_to_b(&wires[0].0).rx, Rx::Keepalive);
    p.clock.advance(25 * S);
    let (wires, _) = p.a.drain(p.clock.now(), &mut p.rng);
    assert_eq!(wires.len(), 1);
    assert_eq!(wires[0].1, SendReason::PersistentKeepalive);
    // Traffic in either direction restarts the interval.
    p.clock.advance(20 * S);
    p.assert_roundtrip_a_to_b(b"traffic");
    assert_eq!(
        p.a.tunnel.timer(Timer::PersistentKeepalive),
        Some(Ticks::from_nanos(p.clock.mono_ns + 25 * S))
    );
}

/// With a persistent keepalive the tunnel brings itself up without any
/// application traffic: handshake first, then the keepalive.
#[test]
fn persistent_keepalive_brings_the_tunnel_up_at_start() {
    let mut p = new_pair_with(152, None, Some(25));
    let now = p.clock.now();
    assert_eq!(p.a.tunnel.next_wake(), Some(Ticks::ZERO), "work at start");
    let init = match p.a.poll(now, &mut p.rng) {
        Polled::Transmit(w, SendReason::HandshakeInitiation, _) => w,
        other => panic!("{other:?}"),
    };
    let resp = match p.deliver_to_b(&init).rx {
        Rx::Response(w) => w,
        other => panic!("{other:?}"),
    };
    assert_eq!(p.deliver_to_a(&resp).rx, Rx::HandshakeComplete);
    let (wires, _) = p.a.drain(now, &mut p.rng);
    assert_eq!(wires.len(), 1, "exactly one keepalive, not two");
    assert_eq!(wires[0].1, SendReason::Keepalive);

    // B has no persistent keepalive and no traffic: it stays quiet.
    let mut q = new_pair(153);
    assert_eq!(q.b.tunnel.next_wake(), None);
    assert_eq!(q.b.poll(q.clock.now(), &mut q.rng), Polled::Idle);
}

/// Persistent keepalive must revive the tunnel after a handshake attempt
/// was abandoned, backing off by one keepalive interval rather than going
/// silent forever or retrying continuously.
#[test]
fn persistent_keepalive_revives_after_giving_up() {
    let mut p = new_pair_with(154, None, Some(25));
    // Drive the first attempt to exhaustion (peer never answers).
    let mut initiations = Vec::new();
    let mut gave_up_at = None;
    for _ in 0..40 {
        let Some(wake) = p.a.tunnel.next_wake() else {
            break;
        };
        let now = p.clock.set(wake);
        let (wires, events) = p.a.drain(now, &mut p.rng);
        initiations.extend(wires.iter().map(|_| p.clock.mono_ns));
        if events.contains(&"handshake_expired") {
            gave_up_at = Some(p.clock.mono_ns);
            break;
        }
    }
    let gave_up_at = gave_up_at.expect("attempt must expire after REKEY_ATTEMPT_TIME");
    let last_initiation = *initiations.last().unwrap();

    // After giving up a deadline is still armed: one keepalive interval
    // after the last initiation.
    let wake = p.a.tunnel.next_wake().expect("revival deadline");
    assert_eq!(wake, Ticks::from_nanos(last_initiation + 25 * S));
    assert!(wake.nanos() > gave_up_at);
    let (wires, _) = p.a.drain(p.clock.set(wake), &mut p.rng);
    assert_eq!(wires.len(), 1);
    assert_eq!(wires[0].1, SendReason::HandshakeInitiation);
}

/// A tunnel with a persistent keepalive keeps itself up, so giving up a
/// handshake must leave it with the next keepalive scheduled.
///
/// The timer is restarted by every message sent. When it fires without a
/// session it asks for a handshake and stays idle until the next
/// initiation goes out — normally the retransmission of the attempt that
/// is under way. That retransmission never comes if the caller is away
/// for longer than Rekey-Attempt-Time at just that point (a suspended
/// laptop, a stopped process): on return the attempt is given up without
/// another message. If nothing restarted the timer there, nothing would
/// ever fire again, and a client behind NAT would stay unreachable until
/// its own application happened to send.
#[test]
fn giving_up_after_a_long_pause_restarts_the_persistent_keepalive() {
    for interval in [1u16, 2, 5] {
        let every = u64::from(interval) * S;
        let mut s = Sim::with_opts(
            52,
            Opts {
                keepalive_a: Some(interval),
                ..Opts::default()
            },
        );
        s.b_off = true; // nobody answers
        // The tunnel brings itself up, and is driven as documented until
        // the persistent timer has fired during the attempt — and no
        // further, so the retransmission is still ahead.
        s.run_until(every);
        assert_eq!(s.times(Who::A, SendReason::HandshakeInitiation), [0]);
        assert_eq!(s.log.len(), 1, "interval {interval}: {:?}", s.log);
        assert_eq!(
            s.p.a.tunnel.timer(Timer::PersistentKeepalive),
            None,
            "interval {interval}: fired, and nothing has restarted it yet"
        );
        assert!(
            s.p.a
                .tunnel
                .timer(Timer::RetransmitHandshake)
                .is_some_and(|at| at.nanos() > s.t()),
            "interval {interval}: the retransmission is still to come"
        );

        // The caller is away for five minutes.
        let back = s.t() + 300 * S;
        s.p.clock.mono_ns = back;
        s.pump();
        assert_eq!(
            s.events,
            [(back, Who::A, "handshake_expired")],
            "interval {interval}"
        );
        assert_eq!(s.log.len(), 1, "given up without another message");
        // One interval later the keepalive is due again; it finds no
        // session and starts a new handshake.
        assert_eq!(
            s.p.a.tunnel.next_wake(),
            Some(Ticks::from_nanos(back + every)),
            "interval {interval}"
        );
        s.run_until(back + every);
        assert_eq!(
            s.times(Who::A, SendReason::HandshakeInitiation),
            [0, back + every],
            "interval {interval}"
        );
    }

    // With an interval longer than Rekey-Timeout the timer is restarted by
    // every retransmission before it can fire, so it is still pending when
    // the caller comes back — and overdue: giving up is followed by the
    // new attempt at once.
    let mut s = Sim::with_opts(
        53,
        Opts {
            keepalive_a: Some(25),
            ..Opts::default()
        },
    );
    s.b_off = true;
    s.run_until(S);
    let back = s.t() + 300 * S;
    s.p.clock.mono_ns = back;
    s.pump();
    assert_eq!(s.events, [(back, Who::A, "handshake_expired")]);
    assert_eq!(s.times(Who::A, SendReason::HandshakeInitiation), [0, back]);
}

#[test]
fn next_wake_never_misses_an_action() {
    // Property: polling strictly before next_wake is always Idle. Walked
    // across an entire handshake-and-traffic lifecycle.
    let mut p = new_pair(52);
    p.establish();
    let wire = p.seal_from_a(b"prime the timers");
    let _ = p.open_at_b(&wire);

    for step in 0..40 {
        let (owner, name) = match (p.a.tunnel.next_wake(), p.b.tunnel.next_wake()) {
            (Some(a), Some(b)) if a <= b => (&mut p.a, "a"),
            (_, Some(_)) => (&mut p.b, "b"),
            (Some(_), None) => (&mut p.a, "a"),
            (None, None) => break,
        };
        let wake = owner.tunnel.next_wake().unwrap();
        if wake.nanos() > p.clock.mono_ns + 1 {
            p.clock.mono_ns = wake.nanos() - 1;
            let r = owner.poll(p.clock.now(), &mut p.rng);
            assert_eq!(
                r,
                Polled::Idle,
                "step {step}: {name} acted before its declared wake"
            );
        }
        p.clock.mono_ns = p.clock.mono_ns.max(wake.nanos());
        let now = p.clock.now();
        let (wires, events) = owner.drain(now, &mut p.rng);
        assert!(
            !wires.is_empty() || !events.is_empty() || owner.tunnel.next_wake() != Some(wake),
            "step {step}: {name} woke for nothing and kept the same deadline"
        );
    }
}

#[test]
fn sending_resets_the_attempt_window() {
    // §6.4: explicit sends reset the 90s give-up counter.
    let mut p = new_pair(53);
    let _ = p.a_initiates();
    // 80s in (still within the window), the app tries to send again.
    p.clock.advance(80 * S);
    assert_eq!(p.a.send(p.clock.now(), b"still trying"), Tx::NoSession);
    // 30s later (110s after the first initiation — past the original 90s
    // window) retransmissions must STILL be running because the window
    // was reset at 80s.
    p.clock.advance(30 * S);
    let (wires, events) = p.a.drain(p.clock.now(), &mut p.rng);
    assert!(events.is_empty(), "gave up too early: window not reset");
    assert!(!wires.is_empty());
}

#[test]
fn clock_jump_far_forward_is_handled() {
    // A caller that sleeps for an hour and polls once must see the
    // discard event exactly once and end quiet, not loop or panic.
    let mut p = new_pair(54);
    p.establish();
    // Leave as much armed as possible before the jump: data both ways.
    p.assert_roundtrip_a_to_b(b"x");
    let wire = p.seal_from_b(b"y");
    let _ = p.open_at_a(&wire);
    let wire = p.seal_from_a(b"unanswered");
    let _ = p.open_at_b(&wire);
    p.clock.advance(3600 * S);
    for side in [&mut p.a, &mut p.b] {
        let (wires, events) = side.drain(p.clock.now(), &mut p.rng);
        assert_eq!(events, vec!["sessions_expired"]);
        assert!(wires.is_empty(), "stale timers must not act: {wires:?}");
        assert_eq!(side.tunnel.next_wake(), None);
    }
}

/// A caller's clock that jumps backwards does not take the tunnel with
/// it: the tunnel goes by the latest instant it has seen, so nothing it
/// arms is ever earlier than something it has already lived through.
#[test]
fn a_clock_that_goes_backwards_is_clamped() {
    let mut p = new_pair(155);
    p.clock.advance(100 * S);
    p.establish();
    let latest = p.clock.now();
    let past = Ticks::from_secs(40);

    // Data sent "a minute ago": the dead-peer timer counts from the
    // latest instant, not from the reading that was passed in.
    let Tx::Transport(wire) = p.a.send(past, b"sent in the past") else {
        panic!("the session is usable")
    };
    dead_peer_deadline(&p.a.tunnel, latest);
    // Data received "a minute ago": likewise the passive keepalive.
    let info = p.b.recv_from(past, a_addr(), false, &wire, &mut p.rng);
    assert!(matches!(info.rx, Rx::Data(_)));
    assert_eq!(
        p.b.tunnel.timer(Timer::SendKeepalive),
        Some(latest.add_nanos(KEEPALIVE_TIMEOUT))
    );
    // Polling with the old reading neither fires anything nor leaves a
    // wake-up that lies in the tunnel's past.
    for side in [&mut p.a, &mut p.b] {
        assert_eq!(side.poll(past, &mut p.rng), Polled::Idle);
        assert!(side.tunnel.next_wake().is_some_and(|wake| wake > latest));
    }

    // Pacing, too, is measured from the latest instant the tunnel has
    // seen.
    let mut p = new_pair(156);
    p.clock.advance(10 * S);
    let _ = p.a_initiates();
    p.a.tunnel.reset();
    p.a.tunnel.request_handshake(Ticks::ZERO);
    assert_eq!(p.a.poll(Ticks::ZERO, &mut p.rng), Polled::Idle);
    assert_eq!(p.a.poll(Ticks::from_secs(14), &mut p.rng), Polled::Idle);
    assert!(matches!(
        p.a.poll(Ticks::from_secs(15), &mut p.rng),
        Polled::Transmit(_, SendReason::HandshakeInitiation, _)
    ));
    assert_eq!(p.a.tunnel.stats().handshakes_initiated, 2);
}

/// An instant beyond `Ticks::MAX` is not a time: `Ticks::from_secs` given
/// milliseconds saturates, and so does any other unit mix-up. Taken at
/// face value it would make every deadline the tunnel has, or will ever
/// arm, due at once and for ever: the keys of a healthy session wiped,
/// and a fresh initiation from every single `poll`. It is treated like a
/// clock that goes backwards instead — for that call, no time has passed.
#[test]
fn an_instant_out_of_range_stops_time_instead_of_ending_it() {
    let absurd_instants = [
        Ticks::from_secs(1_763_000_000_000), // "seconds" that are milliseconds
        Ticks::from_nanos(u64::MAX),
        Ticks::from_nanos(Ticks::MAX.nanos() + 1),
    ];
    assert_eq!(absurd_instants[0].nanos(), u64::MAX);
    // The last instant that is a time is one.
    let mut p = new_pair(157);
    p.clock.set(Ticks::MAX);
    p.establish();
    assert!(p.a.is_established(Ticks::MAX));

    for absurd in absurd_instants {
        // (a) Without a session: a send asks for a handshake, and the
        // handshake is one initiation — then `Idle`, however often the
        // caller polls.
        let mut p = new_pair(158);
        assert_eq!(p.a.send(absurd, b"x"), Tx::NoSession);
        let mut initiations = 0;
        for _ in 0..1000 {
            match p.a.poll(absurd, &mut p.rng) {
                Polled::Transmit(_, SendReason::HandshakeInitiation, _) => initiations += 1,
                Polled::Idle => {}
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(initiations, 1, "{absurd:?}");

        // (b) A healthy session with a persistent keepalive stays as it
        // is: nothing expires, nothing fires, traffic flows.
        let mut p = new_pair_with(159, None, Some(25));
        p.clock.advance(100 * S);
        p.establish();
        let _ = p.a.drain(p.clock.now(), &mut p.rng);
        let sane = p.clock.now();
        let timers_before: Vec<_> = Timer::ALL.iter().map(|t| p.a.tunnel.timer(*t)).collect();
        for _ in 0..100 {
            assert_eq!(p.a.poll(absurd, &mut p.rng), Polled::Idle, "{absurd:?}");
        }
        assert!(p.a.is_established(absurd));
        assert_eq!(p.a.tunnel.stats().handshakes_initiated, 1);
        let timers_now: Vec<_> = Timer::ALL.iter().map(|t| p.a.tunnel.timer(*t)).collect();
        assert_eq!(timers_now, timers_before, "{absurd:?}");
        // When the clock is right again, everything goes on from the
        // last instant that was a time.
        assert_eq!(
            p.a.tunnel.timer(Timer::PersistentKeepalive),
            Some(sane.add_nanos(25 * S))
        );
        let (wires, events) = p.a.drain(p.clock.advance(25 * S), &mut p.rng);
        assert_eq!(events, Vec::<&str>::new());
        assert_eq!(wires.len(), 1);
        assert_eq!(wires[0].1, SendReason::PersistentKeepalive);
        // Traffic flows while the clock is wrong, and what it arms counts
        // from the last instant that was a time, too.
        let latest = p.clock.now();
        let Tx::Transport(wire) = p.a.send(absurd, b"while the clock is wrong") else {
            panic!("the session is usable")
        };
        let info = p.b.recv_from(absurd, a_addr(), false, &wire, &mut p.rng);
        assert!(matches!(info.rx, Rx::Data(_)), "{:?}", info.rx);
        dead_peer_deadline(&p.a.tunnel, latest);
    }
}

/// A response answers the initiation in flight, and an initiation is in
/// flight until its retransmission is due — whether or not the caller has
/// polled since. A caller that was away (a suspended process) and reads
/// its socket before it polls must not start a session the peer derived
/// long ago: it would count the session's age from now, and go on sending
/// on it after the peer has let it expire.
#[test]
fn a_response_is_late_once_its_initiation_is_due_for_retransmission() {
    // The edge, exactly: accepted one nanosecond before the retransmission
    // is due, late at that instant.
    for late in [false, true] {
        let mut p = new_pair(160);
        let init = p.a_initiates();
        let due = p.a.tunnel.timer(Timer::RetransmitHandshake).unwrap();
        let resp = match p.deliver_to_b(&init).rx {
            Rx::Response(w) => w,
            other => panic!("{other:?}"),
        };
        let at = if late {
            due
        } else {
            Ticks::from_nanos(due.nanos() - 1)
        };
        p.clock.set(at);
        let rx = p.deliver_to_a(&resp).rx;
        if late {
            assert_eq!(rx, Rx::Dropped(DropReason::NoPendingHandshake));
            assert!(!p.a.is_established(at));
        } else {
            assert_eq!(rx, Rx::HandshakeComplete);
        }
    }

    // The case it is for: the response has been waiting in the socket
    // buffer for 70 s when the caller comes back, and is read before the
    // timers are run.
    let mut p = new_pair(161);
    let init = p.a_initiates();
    let stale = match p.deliver_to_b(&init).rx {
        Rx::Response(w) => w,
        other => panic!("{other:?}"),
    };
    let back = p.clock.advance(70 * S);
    assert_eq!(
        p.deliver_to_a(&stale).rx,
        Rx::Dropped(DropReason::NoPendingHandshake)
    );
    // The attempt goes on as if the caller had polled first: the next
    // initiation, a response to that, and a session both sides date from
    // the same moment.
    let init = match p.a.poll(back, &mut p.rng) {
        Polled::Transmit(w, SendReason::HandshakeRetransmit, _) => w,
        other => panic!("{other:?}"),
    };
    let resp = match p.deliver_to_b(&init).rx {
        Rx::Response(w) => w,
        other => panic!("{other:?}"),
    };
    assert_eq!(p.deliver_to_a(&resp).rx, Rx::HandshakeComplete);
    for (wire, _) in p.a.drain(back, &mut p.rng).0 {
        assert_eq!(p.deliver_to_b(&wire).rx, Rx::Keepalive);
    }
    // So whatever A may still send, B still accepts: up to the last
    // nanosecond of the session by A's count.
    let last = p.clock.set(back.add_nanos(REJECT_AFTER_TIME - 1));
    assert!(p.a.is_established(last));
    p.assert_roundtrip_a_to_b(b"sent at the last moment");
    assert_eq!(p.b.tunnel.stats().handshakes_responded, 2);
}

#[test]
fn jitter_uses_entropy_but_failure_is_contained() {
    let mut p = new_pair(55);
    let _ = p.a_initiates();
    let wake = p.a.tunnel.next_wake().unwrap();
    let at = p.clock.advance(wake.nanos() + MS);
    // Retransmission needs entropy (new ephemeral + jitter): with a dead
    // rng poll errors but the tunnel survives and the timer stays due.
    assert_eq!(
        p.a.try_poll(at, &mut FailingRng),
        Err(Error::EntropyFailure)
    );
    assert_eq!(p.a.tunnel.next_wake(), Some(wake), "still due");
    assert!(matches!(
        p.a.poll(at, &mut p.rng),
        Polled::Transmit(_, SendReason::HandshakeRetransmit, _)
    ));
}

/// The timer jitter is drawn from the entropy source like the ephemeral
/// key, and a source that fails for it is treated no differently (once it
/// was: the message went out with a jitter of zero): the initiation is
/// not made — and not stranded either. It stays due, and the next call
/// with a source that works sends it.
#[test]
fn entropy_failure_during_jitter_fails_the_call_and_does_not_stall() {
    use wireguard_sans_io::testing::DeterministicRng;
    use wireguard_sans_io::{EntropyError, EntropySource};
    /// Succeeds N times, then fails forever.
    struct CountdownRng {
        inner: DeterministicRng,
        remaining: usize,
    }
    impl EntropySource for CountdownRng {
        fn fill(&mut self, buf: &mut [u8]) -> Result<(), EntropyError> {
            if self.remaining == 0 {
                return Err(EntropyError);
            }
            self.remaining -= 1;
            self.inner.fill(buf)
        }
    }
    let mut p = new_pair(156);
    let now = p.clock.now();
    p.a.tunnel.request_handshake(now);
    // The ephemeral draw succeeds, the jitter draw fails.
    let mut bad = CountdownRng {
        inner: DeterministicRng::new(2),
        remaining: 1,
    };
    assert_eq!(p.a.try_poll(now, &mut bad), Err(Error::EntropyFailure));
    assert_eq!(p.a.tunnel.timer(Timer::RetransmitHandshake), None);
    assert_eq!(p.a.tunnel.stats().handshakes_initiated, 0);
    assert_eq!(p.a.tunnel.next_wake(), Some(now), "still due");
    // With entropy again it goes out, and its retransmission is armed
    // with a jitter.
    assert!(matches!(
        p.a.poll(now, &mut p.rng),
        Polled::Transmit(_, SendReason::HandshakeInitiation, _)
    ));
    let due = p.a.tunnel.timer(Timer::RetransmitHandshake).unwrap();
    assert!((REKEY_TIMEOUT..=REKEY_TIMEOUT + 333_000_000).contains(&due.since(now)));
    let later = p.clock.set(due);
    assert!(matches!(
        p.a.poll(later, &mut p.rng),
        Polled::Transmit(_, SendReason::HandshakeRetransmit, _)
    ));
}

/// A keepalive that comes due when the session has just expired is not
/// dropped: a handshake is started and the keepalive follows it (the
/// kernel stages the keepalive packet and initiates).
#[test]
fn keepalive_without_a_session_starts_a_handshake_and_follows_it() {
    let mut p = new_pair(157);
    p.establish();
    // B receives data 5 s before the session's Reject-After-Time.
    p.clock.advance(REJECT_AFTER_TIME - 5 * S);
    let wire = p.seal_from_a(b"late data");
    let _ = p.open_at_b(&wire);
    // The keepalive falls due at +10 s, when the session is unusable.
    p.clock.advance(KEEPALIVE_TIMEOUT);
    let (wires, _) = p.b.drain(p.clock.now(), &mut p.rng);
    assert_eq!(wires.len(), 1);
    assert_eq!(wires[0].1, SendReason::HandshakeInitiation);
    let resp = match p.deliver_to_a(&wires[0].0).rx {
        Rx::Response(w) => w,
        other => panic!("{other:?}"),
    };
    assert_eq!(p.deliver_to_b(&resp).rx, Rx::HandshakeComplete);
    let (wires, _) = p.b.drain(p.clock.now(), &mut p.rng);
    assert_eq!(wires.len(), 1, "the owed keepalive, once");
    assert_eq!(wires[0].1, SendReason::Keepalive);
}

fn establish_at(p: &mut Pair) {
    p.establish();
}

#[test]
fn idle_established_tunnel_wakes_only_for_the_key_wipe() {
    let mut p = new_pair(158);
    establish_at(&mut p);
    for side in [&p.a, &p.b] {
        assert_eq!(
            side.tunnel.next_wake(),
            Some(Ticks::from_nanos(SESSION_DISCARD_TIME)),
            "an idle tunnel without persistent keepalive sleeps for nine minutes"
        );
    }
}

// ---------------------------------------------------------------------------
// Scenarios, driven like an embedder (next_wake → poll) and checked against
// the reference timer model at every step.
// ---------------------------------------------------------------------------

/// One data packet is lost; the network is perfect afterwards and nobody
/// has anything more to say. The new-handshake timer fires once, the new
/// handshake completes, and that is the end of it.
#[test]
fn one_lost_packet_causes_exactly_one_new_handshake() {
    let mut s = Sim::new(1);
    s.establish(Who::A);
    s.run_until(S);
    s.lose_a_to_b = true;
    assert!(s.send(Who::A, &[0x45; 100]));
    s.lose_a_to_b = false;
    s.run_until(600 * S);

    let handshakes = s.times(Who::A, SendReason::HandshakeInitiation);
    assert_eq!(
        handshakes.len(),
        2,
        "the initial handshake, then exactly one more: {handshakes:?}"
    );
    assert_eq!(handshakes[0], 0);
    let after_the_lost_packet = handshakes[1] - S;
    assert!(
        (DEAD_PEER_TIMEOUT..=DEAD_PEER_TIMEOUT + REKEY_TIMEOUT_JITTER_MAX)
            .contains(&after_the_lost_packet),
        "15 s (and the jitter) after the lost packet: {after_the_lost_packet}"
    );
    assert_eq!(
        s.count(Who::A, SendReason::HandshakeRetransmit, 0, u64::MAX),
        0
    );
    assert_eq!(s.p.a.tunnel.stats().handshakes_completed, 2);
    assert_eq!(
        s.count(Who::B, SendReason::HandshakeInitiation, 0, u64::MAX),
        0
    );
}

/// A streams data to B once a second for a minute; B has nothing to send.
/// B emits a keepalive every Keepalive-Timeout, and A — which hears those —
/// never starts a new handshake.
#[test]
fn one_way_stream_gets_a_keepalive_every_keepalive_timeout() {
    let mut s = Sim::new(2);
    s.establish(Who::A);
    for sec in 1..=60u64 {
        s.run_until(sec * S);
        assert!(s.send(Who::A, &[0x45; 100]));
    }
    assert_eq!(s.data_at_b.len(), 60);
    let keepalives = s.times(Who::B, SendReason::Keepalive);
    // Data at 1 s arms the timer for 11 s; the keepalive at 11 s answers
    // everything so far; the next data packet (also at 11 s) arms it for
    // 21 s; and so on.
    assert_eq!(
        keepalives,
        vec![11 * S, 21 * S, 31 * S, 41 * S, 51 * S],
        "one keepalive per Keepalive-Timeout of unanswered data"
    );
    assert_eq!(
        s.times(Who::A, SendReason::HandshakeInitiation),
        vec![0],
        "the sender hears the keepalives and never suspects a dead peer"
    );
    // The stream stops at 60 s; the packets since the last keepalive get
    // theirs at 61 s, and then both sides are quiet.
    s.run_until(100 * S);
    assert_eq!(s.times(Who::B, SendReason::Keepalive).len(), 6);
    assert_eq!(
        *s.times(Who::B, SendReason::Keepalive).last().unwrap(),
        61 * S
    );
    assert_eq!(s.times(Who::A, SendReason::HandshakeInitiation), vec![0]);
    assert_eq!(
        s.next_wake(),
        Some(SESSION_DISCARD_TIME),
        "nothing left but the wipe"
    );
}

/// B dies while A keeps streaming. A notices 15 s after the first packet
/// that went unanswered — whichever role it had in the handshake — and
/// keeps trying for Rekey-Attempt-Time.
#[test]
fn dead_peer_is_detected_while_streaming() {
    for initiator in [Who::A, Who::B] {
        let mut s = Sim::new(3);
        s.establish(initiator);
        s.run_until(S);
        s.b_off = true;
        let mut first_handshake = None;
        for sec in 1..=40u64 {
            s.run_until(sec * S);
            s.send(Who::A, &[0x45; 100]);
            if first_handshake.is_none() {
                first_handshake = s
                    .log
                    .iter()
                    .find(|(t, w, r)| {
                        *t >= S && *w == Who::A && *r == SendReason::HandshakeInitiation
                    })
                    .map(|(t, _, _)| *t);
            }
        }
        let after_first_unanswered = first_handshake.expect("a new handshake") - S;
        assert!(
            (DEAD_PEER_TIMEOUT..=DEAD_PEER_TIMEOUT + REKEY_TIMEOUT_JITTER_MAX)
                .contains(&after_first_unanswered),
            "session initiator = {initiator:?}: {after_first_unanswered}"
        );
        // Retransmissions follow at Rekey-Timeout (+ jitter) intervals.
        assert!(s.count(Who::A, SendReason::HandshakeRetransmit, 0, 40 * S) >= 3);
    }
}

/// Two-way traffic for ten minutes: sessions are rekeyed on schedule by
/// their initiator, nothing is lost, nobody initiates out of turn.
#[test]
fn steady_two_way_traffic_rekeys_on_schedule() {
    let mut s = Sim::new(4);
    s.establish(Who::A);
    let mut sent = 0usize;
    for tenth in 1..=6000u64 {
        s.run_until(tenth * S / 10);
        assert!(
            s.send(Who::A, b"ping from a"),
            "A lost its session at {tenth}"
        );
        assert!(
            s.send(Who::B, b"pong from b"),
            "B lost its session at {tenth}"
        );
        sent += 1;
    }
    assert_eq!(s.data_at_a.len(), sent);
    assert_eq!(s.data_at_b.len(), sent);
    // 600 s at one rekey per Rekey-After-Time (120 s): the initial
    // handshake plus four rekeys, all initiated by A (the initiator of
    // every session), none retransmitted.
    let a_inits = s.times(Who::A, SendReason::HandshakeInitiation);
    assert_eq!(a_inits.len(), 5, "{a_inits:?}");
    for (i, t) in a_inits.iter().enumerate().skip(1) {
        let expected = i as u64 * REKEY_AFTER_TIME;
        assert!(
            (expected..expected + S).contains(t),
            "rekey {i} at {t} ns, expected ≈ {expected}"
        );
    }
    assert_eq!(
        s.count(Who::B, SendReason::HandshakeInitiation, 0, u64::MAX),
        0
    );
    assert_eq!(
        s.count(Who::A, SendReason::HandshakeRetransmit, 0, u64::MAX),
        0
    );
    // With traffic in both directions nobody ever owes a keepalive, apart
    // from the one that confirms each new session.
    assert_eq!(s.count(Who::B, SendReason::Keepalive, 0, u64::MAX), 0);
    assert!(s.events.is_empty(), "{:?}", s.events);
}

/// A pure responder with persistent keepalive, behind which the initiator
/// roams: every authenticated packet from a new address moves the
/// endpoint, and the responder's keepalives follow it.
#[test]
fn persistent_keepalive_follows_a_roaming_peer() {
    let mut s = Sim::with_opts(
        5,
        Opts {
            keepalive_b: Some(25),
            b_without_endpoint: true,
            ..Opts::default()
        },
    );
    s.establish(Who::A);
    assert_eq!(s.p.b.tunnel.endpoint(), Some(a_addr()));
    // A's NAT mapping changes. The first thing B hears from the new
    // address is a bare keepalive.
    let new_addr: std::net::SocketAddr = "198.51.100.9:61000".parse().unwrap();
    s.p.a.addr = new_addr;
    s.run_until(10 * S);
    let ka = match s.p.a.send(s.p.clock.now(), b"") {
        Tx::Transport(w) => w,
        other => panic!("{other:?}"),
    };
    s.model_a.sent_transport(s.t(), 0);
    s.transmit(Who::A, ka);
    assert_eq!(
        s.p.b.tunnel.endpoint(),
        Some(new_addr),
        "keepalives roam too"
    );
    // B's next persistent keepalive goes to the new address.
    let now = s.p.clock.set(Ticks::from_secs(35));
    match s.p.b.poll(now, &mut s.p.rng) {
        Polled::Transmit(_, SendReason::PersistentKeepalive, dst) => assert_eq!(dst, new_addr),
        other => panic!("{other:?}"),
    }
}

#[test]
fn unanswered_handshake_gives_up_and_reports_it_once() {
    let mut s = Sim::new(6);
    s.b_off = true;
    assert!(!s.send(Who::A, b"hello?"));
    s.run_until(300 * S);
    assert_eq!(s.events.len(), 1, "{:?}", s.events);
    assert_eq!(s.events[0].1, Who::A);
    assert_eq!(s.events[0].2, "handshake_expired");
    assert!(s.events[0].0 >= REKEY_ATTEMPT_TIME);
    assert!(s.events[0].0 < REKEY_ATTEMPT_TIME + REKEY_TIMEOUT + S);
    assert_eq!(s.p.a.tunnel.next_wake(), None);
}

/// Both sides have a persistent keepalive and start at the same instant:
/// each sends its initiation before it has seen the other's, the two
/// cross on the wire, and both handshakes complete. The two sides then
/// settle on the same one of the two sessions — without a retransmission,
/// and so that exactly one of them is its initiator and rekeys it.
///
/// (The wire of this simulation takes time, so that the initiations do
/// cross. With instant delivery the first side's initiation is answered
/// before the second side makes its own, and nothing crosses at all.)
#[test]
fn simultaneous_open_settles() {
    for seed in 7..39u64 {
        let mut s = Sim::with_opts(
            seed,
            Opts {
                keepalive_a: Some(25),
                keepalive_b: Some(25),
                ..Opts::default()
            },
        );
        s.crossing_wire = true;
        s.pump();
        // They crossed: each side made an initiation at time zero, each
        // answered the other's, and each completed its own.
        for who in [Who::A, Who::B] {
            assert_eq!(s.times(who, SendReason::HandshakeInitiation), [0]);
        }
        let stats = [s.p.a.tunnel.stats(), s.p.b.tunnel.stats()];
        for st in stats {
            assert_eq!(st.handshakes_responded, 1, "seed {seed}");
            assert_eq!(st.handshakes_initiated, 1, "seed {seed}");
        }
        let now = s.p.clock.now();
        assert!(s.p.a.is_established(now) && s.p.b.is_established(now));

        // Traffic both ways, every second, across the first rekey.
        for sec in 1..=200u64 {
            s.run_until(sec * S);
            assert!(s.send(Who::A, &[0xa0; 40]), "seed {seed}: A at {sec} s");
            assert!(s.send(Who::B, &[0xb0; 40]), "seed {seed}: B at {sec} s");
        }
        s.run_until(201 * S);
        assert_eq!(s.data_at_b.len(), 200, "seed {seed}");
        assert_eq!(s.data_at_a.len(), 200, "seed {seed}");
        assert!(s.events.is_empty(), "seed {seed}: {:?}", s.events);
        for who in [Who::A, Who::B] {
            assert_eq!(
                s.count(who, SendReason::HandshakeRetransmit, 0, u64::MAX),
                0,
                "seed {seed}"
            );
        }
        // One session is in use, so exactly one side is its initiator —
        // and that side, alone, rekeys it when it is two minutes old.
        let rekeys: Vec<(u64, Who)> = s
            .log
            .iter()
            .filter(|(t, _, why)| *t > 0 && *why == SendReason::HandshakeInitiation)
            .map(|(t, who, _)| (*t, *who))
            .collect();
        assert_eq!(rekeys.len(), 1, "seed {seed}: {rekeys:?}");
        assert!(
            (REKEY_AFTER_TIME..REKEY_AFTER_TIME + 2 * S).contains(&rekeys[0].0),
            "seed {seed}: {rekeys:?}"
        );
    }
}
