//! `next_wake()` and `poll()` read the same timer table, so they cannot
//! disagree. These tests lock that in the way the two historical
//! divergences were found: by driving tunnels purely by
//! `next_wake()`/`poll()` and checking, at every single step, that a
//! tunnel which reports `Idle` asks for a wake-up strictly in the future.
//!
//! History (both fixed by construction now):
//!
//! * `next_wake()` tested `current.is_some()` while `poll()` tested
//!   whether the session was usable; with the session past
//!   Reject-After-Time and a persistent keepalive set, `next_wake()`
//!   returned a stale deadline that `poll()` could never satisfy, so the
//!   caller busy-looped at 100 % CPU.
//! * `next_wake()`'s discard horizon counted an unconfirmed responder
//!   session that `poll()` dropped first, delaying the key wipe by up to
//!   360 s.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;
use common::{Opts, S, Sim, Who};
use wireguard_sans_io::SendReason;

/// Every combination of persistent keepalive × who initiated × what the
/// peer does afterwards, each run for twenty minutes of simulated time.
/// `Sim` asserts the wake-up invariant (and the reference timer model)
/// after every poll.
#[test]
fn no_wake_up_is_ever_due_after_idle() {
    #[derive(Debug, Clone, Copy)]
    enum Peer {
        Alive,
        DiesAt(u64),
        LossyFrom(u64),
    }
    let mut runs = 0;
    for keepalive_a in [None, Some(25), Some(1)] {
        for keepalive_b in [None, Some(25)] {
            for initiator in [Who::A, Who::B] {
                for peer in [
                    Peer::Alive,
                    Peer::DiesAt(119),
                    Peer::DiesAt(200),
                    Peer::LossyFrom(30),
                ] {
                    for traffic in [false, true] {
                        let mut s = Sim::with_opts(
                            0xb00b + runs,
                            Opts {
                                keepalive_a,
                                keepalive_b,
                                ..Opts::default()
                            },
                        );
                        runs += 1;
                        s.establish(initiator);
                        let mut wakes = 0u64;
                        for sec in 1..=1200u64 {
                            match peer {
                                Peer::DiesAt(t) if sec == t => s.b_off = true,
                                Peer::LossyFrom(t) if sec >= t => s.lose_b_to_a = sec % 3 != 0,
                                _ => {}
                            }
                            let before = s.log.len() + s.events.len();
                            s.run_until(sec * S);
                            wakes += (s.log.len() + s.events.len() - before) as u64;
                            if traffic && sec % 7 == 0 {
                                s.send(Who::A, b"some traffic");
                            }
                        }
                        // Bounded activity: nothing may fire more often
                        // than the fastest timer in play allows.
                        assert!(
                            wakes < 4000,
                            "{keepalive_a:?}/{keepalive_b:?}/{initiator:?}/{peer:?}/{traffic}: \
                             {wakes} timer actions in 1200 s"
                        );
                    }
                }
            }
        }
    }
    assert_eq!(runs, 96);
}

/// The original scenario: persistent keepalive, a session that expires
/// while the peer is silent. The tunnel keeps trying — on schedule, not in
/// a spin.
#[test]
fn expired_session_with_persistent_keepalive_and_silent_peer() {
    let mut s = Sim::with_opts(
        0xb00b,
        Opts {
            keepalive_a: Some(25),
            ..Opts::default()
        },
    );
    s.establish(Who::A);
    s.run_until(119 * S);
    assert!(s.send(Who::A, b"last words"));
    s.b_off = true;
    s.run_until(540 * S);
    let initiations = s.count(Who::A, SendReason::HandshakeInitiation, 120 * S, 540 * S)
        + s.count(Who::A, SendReason::HandshakeRetransmit, 120 * S, 540 * S);
    // One handshake message per Rekey-Timeout at the very most.
    assert!(initiations > 10, "it did keep trying: {initiations}");
    assert!(initiations <= 420 / 5 + 1, "paced: {initiations}");
}
