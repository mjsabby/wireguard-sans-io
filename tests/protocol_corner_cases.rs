//! State-machine corner cases, ordering invariants, and protocol-edge
//! behaviour.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;
use common::{
    BASE_UNIX, MS, Pair, Polled, Rx, RxInfo, S, Tx, a_addr, b_addr, new_pair, new_pair_with,
};
use core::num::NonZeroU16;
use wireguard_sans_io::testing::DeterministicRng;
use wireguard_sans_io::{
    DropReason, EntropyError, EntropySource, Error, SendReason, Ticks, Timer, WallClock, consts,
};

// ----------------------------------------------------------------------------
// The greatest timestamp is committed atomically with the new session — an
// initiation that passes the timestamp check but then fails on entropy
// (for the response ephemeral) does NOT advance it, so the SAME initiation
// can be retried once entropy recovers. Conversely, an initiation that is
// fully processed advances it exactly once.
// ----------------------------------------------------------------------------
#[test]
fn greatest_timestamp_commits_atomically_with_response() {
    struct FailAfterN {
        inner: DeterministicRng,
        left: u32,
    }
    impl EntropySource for FailAfterN {
        fn fill(&mut self, b: &mut [u8]) -> Result<(), EntropyError> {
            if self.left == 0 {
                return Err(EntropyError);
            }
            self.left -= 1;
            self.inner.fill(b)
        }
    }

    let mut p = new_pair(0xD1);
    let now = p.clock.now();
    let init = p.a_initiates();

    // B's entropy fails on the FIRST draw (the response ephemeral).
    let mut bad = FailAfterN {
        inner: DeterministicRng::new(7),
        left: 0,
    };
    assert_eq!(
        p.b.try_recv_from(now, a_addr(), false, &init, &mut bad)
            .err(),
        Some(Error::EntropyFailure)
    );
    assert_eq!(p.b.tunnel.next_wake(), None, "no timer was armed");
    assert_eq!(p.b.tunnel.endpoint(), Some(a_addr()));
    // The SAME initiation, replayed with working entropy, must now be
    // ACCEPTED — because the timestamp was not recorded.
    let mut good = DeterministicRng::new(8);
    assert!(matches!(
        p.b.recv_from(now, a_addr(), false, &init, &mut good).rx,
        Rx::Response(_)
    ));
    // And a SECOND replay is now rejected (timestamp committed).
    assert_eq!(
        p.b.recv_from(now, a_addr(), false, &init, &mut good).rx,
        Rx::Dropped(DropReason::ReplayedTimestamp)
    );
}

// ----------------------------------------------------------------------------
// Receiving a transport datagram on `previous` does NOT promote it or
// otherwise displace `current`.
// ----------------------------------------------------------------------------
#[test]
fn transport_on_previous_does_not_displace_current() {
    let mut p = new_pair(0xD2);
    p.establish();
    let on_old = p.seal_from_a(b"old session");
    // Rekey: A.previous = old current.
    p.clock.advance(6 * S);
    let init = p.a_initiates();
    let resp = match p.deliver_to_b(&init).rx {
        Rx::Response(w) => w,
        other => panic!("{other:?}"),
    };
    assert_eq!(p.deliver_to_a(&resp).rx, Rx::HandshakeComplete);
    let on_new = p.seal_from_a(b"new session");
    p.open_at_b(&on_new); // promotes B.next → B.current
    // Now deliver the OLD packet (hits B.previous).
    let info = p.deliver_to_b(&on_old);
    assert!(matches!(&info.rx, Rx::Data(d) if &d[..11] == b"old session"));
    assert!(!info.session_established);
    // B.current is still the NEW session: another packet on it works.
    let on_new2 = p.seal_from_a(b"still new");
    assert_eq!(&p.open_at_b(&on_new2)[..9], b"still new");
    // …and B itself sends on the new session: its datagrams are addressed
    // to the index A chose in the second initiation.
    let from_b = p.seal_from_b(b"reply");
    assert_eq!(&from_b[4..8], &init[4..8], "B addresses A's NEW index");
}

/// The same from the side that initiated the old session: when the peer
/// rekeys, we move to its session — and a packet of the peer's that was
/// still in flight on the old one, which we initiated, does not take us
/// back there.
#[test]
fn a_late_packet_on_the_old_session_does_not_take_us_back_to_it() {
    let mut p = new_pair(0xD3);
    p.establish(); // A initiated this session
    let on_old = p.seal_from_b(b"old session");
    // B rekeys; A answers and moves to the new session on B's first packet.
    p.clock.advance(6 * S);
    let init = p.b_initiates();
    let resp = response(p.deliver_to_a(&init));
    assert_eq!(p.deliver_to_b(&resp).rx, Rx::HandshakeComplete);
    let on_new = p.seal_from_b(b"new session");
    let info = p.deliver_to_a(&on_new);
    assert!(
        info.session_established,
        "A moved to the session B initiated"
    );
    // B's late packet arrives on the old session — A's "previous".
    let info = p.deliver_to_a(&on_old);
    assert!(matches!(&info.rx, Rx::Data(d) if &d[..11] == b"old session"));
    assert!(!info.session_established);
    // A still sends on the new session: its datagrams are addressed to
    // the index B chose in its initiation.
    let from_a = p.seal_from_a(b"reply");
    assert_eq!(&from_a[4..8], &init[4..8], "A addresses B's NEW index");
    assert_eq!(&p.open_at_b(&from_a)[..5], b"reply");
}

// ----------------------------------------------------------------------------
// Handshake timestamps and a wall clock that was wrong.
//
// (a) Outbound timestamps are ratcheted: after a far-future wall clock is
//     corrected (`set_wall_clock`), our later initiations still carry
//     strictly increasing timestamps, so the peer keeps accepting them.
//
// (b) A peer that does NOT ratchet (kernel, wireguard-go) and once sent a
//     far-future timestamp is poisoned until real time catches up — and
//     `reset()` on our side deliberately does NOT clear the record. We
//     model that peer with a second initiator that never saw the future.
// ----------------------------------------------------------------------------
#[test]
fn tai64n_poisoning_and_ratchet_self_healing() {
    let mut p = new_pair(0xD3);
    // A's wall clock is wildly wrong at first.
    p.a.tunnel
        .set_wall_clock(WallClock::new(Ticks::ZERO, u64::MAX, 999_999_999));
    let init1 = p.a_initiates();
    assert!(matches!(p.deliver_to_b(&init1).rx, Rx::Response(_)));

    // (a) A learns the real time. Its next initiation is still accepted.
    p.clock.advance(6 * S);
    p.a.tunnel
        .set_wall_clock(WallClock::new(p.clock.now(), BASE_UNIX + 6, 0));
    let init2 = p.a_initiates();
    assert!(
        matches!(p.deliver_to_b(&init2).rx, Rx::Response(_)),
        "the outbound ratchet must keep timestamps increasing"
    );

    // (b) A NON-ratcheting peer at the same point would send the real
    //     time, which is < the poisoned value. B must reject it.
    let mut q = new_pair(0xD3); // same keys (deterministic)
    q.clock.advance(6 * S);
    let kernel_style = q.a_initiates();
    assert_eq!(
        p.deliver_to_b(&kernel_style).rx,
        Rx::Dropped(DropReason::ReplayedTimestamp),
        "a non-ratcheting peer IS poisoned (documented; needs a new Tunnel to clear)"
    );
    // reset() retains the greatest timestamp (documented in Tunnel::reset).
    p.b.tunnel.reset();
    p.clock.advance(6 * S);
    q.clock.advance(6 * S);
    let kernel_style2 = q.a_initiates();
    assert_eq!(
        p.deliver_to_b(&kernel_style2).rx,
        Rx::Dropped(DropReason::ReplayedTimestamp),
        "reset() deliberately does not clear the greatest timestamp"
    );
}

/// Two initiations inside one timestamp-whitening quantum (≈16.7 ms) still
/// carry strictly increasing timestamps.
#[test]
fn timestamps_increase_even_within_one_whitening_quantum() {
    let mut p = new_pair(0xD8);
    let init1 = p.a_initiates();
    assert!(matches!(p.deliver_to_b(&init1).rx, Rx::Response(_)));
    // The monotonic clock moves 6 s, but the wall-clock anchor is moved
    // back by the same amount: the raw timestamp would be identical.
    p.clock.advance(6 * S);
    p.a.tunnel
        .set_wall_clock(WallClock::new(p.clock.now(), BASE_UNIX, 0));
    let init2 = p.a_initiates();
    assert!(
        matches!(p.deliver_to_b(&init2).rx, Rx::Response(_)),
        "an identical wall-clock reading must not look like a replay"
    );
}

// ----------------------------------------------------------------------------
// poll() with a tiny output buffer returns BufferTooSmall and does NOT
// corrupt timer state (next poll with adequate buffer works).
// ----------------------------------------------------------------------------
#[test]
fn poll_buffer_too_small_is_recoverable() {
    let mut p = new_pair(0xD4);
    let _ = p.a_initiates();
    let later = p.clock.advance(6 * S);
    let before = p.a.tunnel.next_wake();
    // Retransmit due, but buffer too small for the initiation.
    let mut tiny = [0u8; 16];
    assert_eq!(
        p.a.tunnel.poll(later, &mut tiny, &mut p.rng).err(),
        Some(Error::BufferTooSmall)
    );
    assert_eq!(p.a.tunnel.next_wake(), before, "the timer is still due");
    // Adequate buffer: retransmit succeeds.
    assert!(matches!(
        p.a.poll(later, &mut p.rng),
        Polled::Transmit(_, SendReason::HandshakeRetransmit, _)
    ));
}

// ----------------------------------------------------------------------------
// encapsulate() with a payload that is EXACTLY at a 16-byte boundary adds
// ZERO padding (whitepaper §5.4.6).
// ----------------------------------------------------------------------------
#[test]
fn aligned_payloads_get_zero_padding() {
    let mut p = new_pair(0xD5);
    p.establish();
    for n in [16usize, 32, 1408, 1424, 1440] {
        let wire = p.seal_from_a(&vec![0x77u8; n]);
        assert_eq!(
            wire.len(),
            n + 32,
            "{n}-byte payload should encode to exactly {}+32",
            n
        );
        let got = p.open_at_b(&wire);
        assert_eq!(got.len(), n);
    }
}

// ----------------------------------------------------------------------------
// The 5-second initiation pacing applies to send-triggered initiations
// too, and survives reset().
// ----------------------------------------------------------------------------
#[test]
fn send_triggered_initiation_is_paced() {
    let mut p = new_pair(0xD6);
    let now = p.clock.now();
    // First send: a handshake is requested and goes out.
    assert_eq!(p.a.send(now, b"x"), Tx::NoSession);
    assert!(matches!(
        p.a.poll(now, &mut p.rng),
        Polled::Transmit(_, SendReason::HandshakeInitiation, _)
    ));
    // Reset to clear the in-flight handshake, then try again within the
    // pacing window: nothing may be sent yet.
    p.a.tunnel.reset();
    assert_eq!(p.a.send(now, b"x"), Tx::NoSession);
    assert_eq!(p.a.poll(now, &mut p.rng), Polled::Idle);
    assert_eq!(
        p.a.tunnel.timer(Timer::SendInitiation),
        Some(Ticks::from_nanos(consts::REKEY_TIMEOUT)),
        "pacing must survive reset()"
    );
    // After REKEY_TIMEOUT, allowed.
    let later = p.clock.advance(consts::REKEY_TIMEOUT);
    assert!(matches!(
        p.a.poll(later, &mut p.rng),
        Polled::Transmit(_, SendReason::HandshakeInitiation, _)
    ));
}

// ----------------------------------------------------------------------------
// The receive path does not enforce 16-byte alignment: a sender that
// clamps its padding to a non-16-aligned MTU (as the kernel does) produces
// ciphertext of any length, and it must decrypt.
// ----------------------------------------------------------------------------
#[test]
fn receive_accepts_unaligned_ciphertext() {
    let mut p = new_pair(0xD7);
    p.establish();
    for mtu in [13u16, 21, 1350, 1419] {
        p.a.tunnel.set_mtu(NonZeroU16::new(mtu));
        let payload = vec![0x5au8; usize::from(mtu)];
        let wire = p.seal_from_a(&payload);
        assert_eq!(wire.len(), usize::from(mtu) + 32, "no padding at the MTU");
        assert_eq!(p.open_at_b(&wire), payload, "mtu={mtu}");
    }
    // Structural acceptance of every body length.
    for ct_len in [0usize, 1, 13, 16, 17, 1350, 65000] {
        let mut dg = vec![0u8; 16 + ct_len + 16];
        wireguard_sans_io::message::write_transport_header(&mut dg, 0x1234, 7).unwrap();
        assert!(
            wireguard_sans_io::peek(&dg).is_ok(),
            "parse must accept ct_len={ct_len} (non-16-aligned)"
        );
    }
}

// ----------------------------------------------------------------------------
// Confirming a responder session clears any in-flight handshake of our own
// (a rekey raced by the peer's initiation): no redundant retransmissions
// for up to 90 s, and a late response to the abandoned initiation is not
// accepted.
// ----------------------------------------------------------------------------
#[test]
fn responder_promotion_clears_own_inflight() {
    let mut p = new_pair(0xD9);
    // B starts its OWN handshake; the initiation is delayed in the
    // network.
    let b_init = p.b_initiates();
    // Meanwhile A initiates; B responds (next set, own handshake still
    // in flight).
    let a_init = p.a_initiates();
    let resp = match p.deliver_to_b(&a_init).rx {
        Rx::Response(w) => w,
        other => panic!("{other:?}"),
    };
    assert!(p.b.tunnel.timer(Timer::RetransmitHandshake).is_some());
    assert_eq!(p.deliver_to_a(&resp).rx, Rx::HandshakeComplete);
    // A's first transport confirms B's `next` → promotion.
    let data = p.seal_from_a(b"hi");
    let info = p.deliver_to_b(&data);
    assert!(info.session_established);
    assert_eq!(
        p.b.tunnel.timer(Timer::RetransmitHandshake),
        None,
        "the redundant handshake must stop retransmitting"
    );
    // B's delayed initiation finally reaches A, which answers it…
    let late_resp = match p.deliver_to_a(&b_init).rx {
        Rx::Response(w) => w,
        other => panic!("{other:?}"),
    };
    // …but B no longer has that handshake in flight.
    assert_eq!(
        p.deliver_to_b(&late_resp).rx,
        Rx::Dropped(DropReason::NoPendingHandshake)
    );
    // Nothing is pending on B for the next two minutes of quiet.
    let later = p.clock.advance(6 * S);
    let (wires, events) = p.b.drain(later, &mut p.rng);
    assert!(
        wires.iter().all(|(_, why)| *why == SendReason::Keepalive),
        "{wires:?}"
    );
    assert!(events.is_empty());
}

// ----------------------------------------------------------------------------
// Crossed handshakes: both sides initiate before either hears the other.
//
// This implementation answers the peer's initiation and keeps its own in
// flight. What happens next depends on the peer:
//
// * a peer that runs one handshake at a time (the Linux kernel) answers
//   ours and drops its own, so ours completes within one round trip;
// * a peer that also keeps its own (this implementation on both ends)
//   completes too, and both sides must then settle on ONE of the two
//   sessions, so that exactly one side is its initiator and rekeys it.
//
// Not a crossing, although it leaves the same two sessions behind: we
// answered the peer's initiation and only later started a handshake of our
// own. Then ours is the newer session and the peer will switch to it.
// ----------------------------------------------------------------------------

fn index_at(wire: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(wire[at..at + 4].try_into().unwrap())
}

fn response(info: RxInfo) -> Vec<u8> {
    match info.rx {
        Rx::Response(w) => w,
        other => panic!("expected a handshake response, got {other:?}"),
    }
}

/// Run both sides' timers to quiescence at `now`, delivering whatever
/// they send — and the responses to it — at once. Returns the reasons of
/// the handshake initiations each side sent: `[A's, B's]`.
fn settle(p: &mut Pair, now: Ticks) -> [Vec<SendReason>; 2] {
    let mut initiations = [Vec::new(), Vec::new()];
    loop {
        let mut quiet = true;
        for from_a in [true, false] {
            loop {
                let polled = if from_a {
                    p.a.poll(now, &mut p.rng)
                } else {
                    p.b.poll(now, &mut p.rng)
                };
                let (wire, why) = match polled {
                    Polled::Transmit(wire, why, _) => (wire, why),
                    Polled::Idle => break,
                    other => panic!("unexpected {other:?}"),
                };
                quiet = false;
                if matches!(
                    why,
                    SendReason::HandshakeInitiation | SendReason::HandshakeRetransmit
                ) {
                    initiations[usize::from(!from_a)].push(why);
                }
                let info = if from_a {
                    p.deliver_to_b(&wire)
                } else {
                    p.deliver_to_a(&wire)
                };
                if let Rx::Response(reply) = info.rx {
                    let info = if from_a {
                        p.deliver_to_a(&reply)
                    } else {
                        p.deliver_to_b(&reply)
                    };
                    assert_eq!(info.rx, Rx::HandshakeComplete);
                }
            }
        }
        if quiet {
            return initiations;
        }
    }
}

/// The peer runs one handshake at a time, as the Linux kernel does: when
/// our initiation crosses its own it answers ours and drops its own, so
/// our answer to its initiation finds nothing waiting. Our handshake must
/// complete with the peer's answer — one round trip after we initiated —
/// and leave both ends in clean roles, with nothing retransmitted.
///
/// (Had we dropped our initiation as well, neither side would have a
/// session until a retransmission five seconds later, and with traffic
/// queued on both sides those cross again. Measured against the kernel
/// over a 200 ms link: no session in 30 s that way, 0.4 s this way.)
#[test]
fn crossed_handshake_with_a_peer_that_gives_way_completes_at_once() {
    let mut p = new_pair(0xC054);
    p.b.tunnel.set_endpoint(a_addr());
    // Both initiations are on the wire before either arrives. B plays the
    // peer that gives way: A's answer to B's initiation is never
    // delivered, exactly as if B had dropped that handshake.
    let init_a = p.a_initiates();
    let init_b = p.b_initiates();
    let _never_delivered = response(p.deliver_to_a(&init_b));
    let resp_b = response(p.deliver_to_b(&init_a));

    // B's answer to OUR initiation completes it, although we have
    // answered B's initiation in the meantime.
    let info = p.deliver_to_a(&resp_b);
    assert_eq!(info.rx, Rx::HandshakeComplete);
    assert!(info.session_established);
    let now = p.clock.now();
    assert!(p.a.is_established(now));
    // Our confirmation makes it usable for B, which stops its own attempt.
    assert_eq!(settle(&mut p, now), [vec![], vec![]]);
    assert!(p.b.is_established(now));
    assert_eq!(p.a.tunnel.timer(Timer::RetransmitHandshake), None);
    assert_eq!(p.b.tunnel.timer(Timer::RetransmitHandshake), None);
    // Both ends use the session A initiated.
    assert_eq!(index_at(&p.seal_from_a(b"a to b"), 4), index_at(&resp_b, 4));
    assert_eq!(index_at(&p.seal_from_b(b"b to a"), 4), index_at(&init_a, 4));

    // Traffic both ways for 200 s: never without a session, the one rekey
    // comes from A (the initiator), and the session A had answered for
    // B's dropped handshake — which nobody ever used — expires by itself.
    assert!(p.a.tunnel.timer(Timer::ExpireNextSession).is_some());
    let (mut rekeys_a, mut rekeys_b) = (0, 0);
    for second in 1..=200u64 {
        let now = p.clock.set(Ticks::from_nanos(second * S));
        let wire = p.seal_from_a(b"a to b");
        assert_eq!(&p.open_at_b(&wire)[..6], b"a to b");
        let wire = p.seal_from_b(b"b to a");
        assert_eq!(&p.open_at_a(&wire)[..6], b"b to a");
        let [a, b] = settle(&mut p, now);
        assert!(
            a.iter()
                .chain(&b)
                .all(|why| *why == SendReason::HandshakeInitiation),
            "at {second} s"
        );
        rekeys_a += a.len();
        rekeys_b += b.len();
    }
    assert_eq!((rekeys_a, rekeys_b), (1, 0));
    assert_eq!(p.a.tunnel.timer(Timer::ExpireNextSession), None);
}

/// Both ends are this implementation, so both handshakes complete. Both
/// sides must then settle on ONE of the two sessions. (When each side
/// simply switched to the other's session, both ended up responder of the
/// session they sent on: nobody rekeyed, both stalled at
/// Reject-After-Time, and the two re-handshakes crossed again — every
/// three minutes.)
#[test]
fn crossed_handshakes_settle_on_one_session() {
    let (mut a_won, mut b_won) = (0, 0);
    for seed in 0..48u64 {
        let mut p = new_pair(0xC055_0000 + seed);
        p.b.tunnel.set_endpoint(a_addr());
        let init_a = p.a_initiates();
        let init_b = p.b_initiates();
        let resp_a = response(p.deliver_to_a(&init_b));
        let resp_b = response(p.deliver_to_b(&init_a));
        assert_eq!(p.deliver_to_a(&resp_b).rx, Rx::HandshakeComplete);
        assert_eq!(p.deliver_to_b(&resp_a).rx, Rx::HandshakeComplete);
        // Each confirms its own session with a keepalive; those cross too.
        let now = p.clock.now();
        let keepalive = |polled: Polled| match polled {
            Polled::Transmit(w, SendReason::Keepalive, _) => w,
            other => panic!("{other:?}"),
        };
        let ka_a = keepalive(p.a.poll(now, &mut p.rng));
        let ka_b = keepalive(p.b.poll(now, &mut p.rng));
        let at_b = p.deliver_to_b(&ka_a);
        let at_a = p.deliver_to_a(&ka_b);
        assert_eq!((&at_a.rx, &at_b.rx), (&Rx::Keepalive, &Rx::Keepalive));
        // Exactly one side switched to the session the other initiated.
        assert_ne!(
            at_a.session_established, at_b.session_established,
            "seed {seed}: both sides (or neither) switched sessions"
        );

        // The two sessions, by the indices on the wire: A's handshake is
        // (init_a sender, resp_b sender), B's is (init_b sender, resp_a
        // sender). The one with the smaller pair wins.
        let session_a = (index_at(&init_a, 4), index_at(&resp_b, 4));
        let session_b = (index_at(&init_b, 4), index_at(&resp_a, 4));
        let a_wins = session_a < session_b;
        assert_eq!(at_b.session_established, a_wins, "seed {seed}");
        if a_wins {
            a_won += 1;
        } else {
            b_won += 1;
        }
        // Both directions now use the winning session: a transport
        // message names the RECEIVER's index for it.
        let (to_b, to_a) = if a_wins {
            (session_a.1, session_a.0)
        } else {
            (session_b.0, session_b.1)
        };
        assert_eq!(index_at(&p.seal_from_a(b"a to b"), 4), to_b, "seed {seed}");
        assert_eq!(index_at(&p.seal_from_b(b"b to a"), 4), to_a, "seed {seed}");

        // Seven minutes of traffic both ways, once a second: no send ever
        // finds the tunnel without a session, and the rekeys all come
        // from the one side that initiated the winning session.
        let (mut rekeys_a, mut rekeys_b) = (0, 0);
        for second in 1..=420u64 {
            let now = p.clock.set(Ticks::from_nanos(second * S));
            let wire = p.seal_from_a(b"a to b");
            assert_eq!(&p.open_at_b(&wire)[..6], b"a to b");
            let wire = p.seal_from_b(b"b to a");
            assert_eq!(&p.open_at_a(&wire)[..6], b"b to a");
            let [a, b] = settle(&mut p, now);
            assert!(
                a.iter()
                    .chain(&b)
                    .all(|why| *why == SendReason::HandshakeInitiation),
                "seed {seed} at {second} s"
            );
            rekeys_a += a.len();
            rekeys_b += b.len();
        }
        let expected = if a_wins { (3, 0) } else { (0, 3) };
        assert_eq!(
            (rekeys_a, rekeys_b),
            expected,
            "seed {seed}: rekeys at 120, 240 and 360 s, all from the winning session's initiator"
        );
    }
    assert!(
        a_won > 8 && b_won > 8,
        "both outcomes of the tie-break are covered: {a_won} / {b_won}"
    );
}

/// The two sides can disagree about whether their handshakes crossed. If
/// the network holds our initiation back for longer than the peer's whole
/// handshake takes, then for us the two crossed (we answered the peer
/// while ours was in flight) — and for the peer they did not (its own
/// handshake was complete before ours arrived, so ours is simply the
/// newer one, and it switches to it). When the peer's first packet on its
/// own session then reaches us late, the tie-break alone can send us the
/// other way: to the peer's session, which the peer has already left.
/// Each side is then the responder of the session it sends on, nobody
/// rekeys, and both run out of session at Reject-After-Time.
///
/// What settles it is what the peer actually does: it is sending on the
/// session we initiated, so that is the one to use.
#[test]
fn a_delayed_initiation_does_not_leave_the_two_sides_on_different_sessions() {
    let (mut kept, mut switched_and_came_back) = (0, 0);
    for seed in 0..48u64 {
        let mut p = new_pair(0xDE1A_0000 + seed);
        p.b.tunnel.set_endpoint(a_addr());
        let now = p.clock.now();
        let keepalive = |polled: Polled| match polled {
            Polled::Transmit(w, SendReason::Keepalive, _) => w,
            other => panic!("{other:?}"),
        };
        // A initiates; the network holds the initiation back.
        let init_a = p.a_initiates();
        // Meanwhile B's whole handshake goes through: A answers it (with
        // its own initiation still in flight), B completes and confirms —
        // but that confirmation is held back too.
        let init_b = p.b_initiates();
        let resp_a = response(p.deliver_to_a(&init_b));
        assert_eq!(p.deliver_to_b(&resp_a).rx, Rx::HandshakeComplete);
        let late_from_b = keepalive(p.b.poll(now, &mut p.rng));
        // Now A's initiation arrives. To B it is a new handshake from the
        // peer; B answers, A completes and confirms, and B switches to
        // A's session — the newer one.
        let resp_b = response(p.deliver_to_b(&init_a));
        assert_eq!(p.deliver_to_a(&resp_b).rx, Rx::HandshakeComplete);
        let ka_a = keepalive(p.a.poll(now, &mut p.rng));
        let at_b = p.deliver_to_b(&ka_a);
        assert_eq!(at_b.rx, Rx::Keepalive);
        assert!(at_b.session_established, "seed {seed}: B uses A's session");
        // B's old confirmation arrives at last, on the session B has left.
        // For A the handshakes crossed, and the indices decide whether it
        // switches.
        let at_a = p.deliver_to_a(&late_from_b);
        assert_eq!(at_a.rx, Rx::Keepalive);
        if at_a.session_established {
            switched_and_came_back += 1;
        } else {
            kept += 1;
        }

        // Whatever A did there: once traffic flows, both sides are on A's
        // session — the one B is using. A transport message names the
        // receiver's index for the session it was sent on.
        let (a_index, b_index) = (index_at(&init_a, 4), index_at(&resp_b, 4));
        for _ in 0..2 {
            let wire = p.seal_from_b(b"b to a");
            assert_eq!(index_at(&wire, 4), a_index, "seed {seed}");
            assert_eq!(&p.open_at_a(&wire)[..6], b"b to a");
            let wire = p.seal_from_a(b"a to b");
            assert_eq!(&p.open_at_b(&wire)[..6], b"a to b");
        }
        assert_eq!(
            index_at(&p.seal_from_a(b"a to b"), 4),
            b_index,
            "seed {seed}: A sends on the session B is using"
        );

        // Seven minutes of traffic both ways: never without a session, and
        // every rekey comes from A, the initiator of that session.
        let (mut rekeys_a, mut rekeys_b) = (0, 0);
        for second in 1..=420u64 {
            let now = p.clock.set(Ticks::from_nanos(second * S));
            let wire = p.seal_from_a(b"a to b");
            assert_eq!(&p.open_at_b(&wire)[..6], b"a to b");
            let wire = p.seal_from_b(b"b to a");
            assert_eq!(&p.open_at_a(&wire)[..6], b"b to a");
            let [a, b] = settle(&mut p, now);
            rekeys_a += a.len();
            rekeys_b += b.len();
        }
        assert_eq!((rekeys_a, rekeys_b), (3, 0), "seed {seed}");
    }
    assert!(
        kept > 8 && switched_and_came_back > 8,
        "both outcomes of the tie-break are covered: {kept} / {switched_and_came_back}"
    );
}

/// §6.3 counts the key wipe from the newest session. When the tie-break
/// makes one side switch to the session the peer initiated — which that
/// side derived a little earlier than the one it initiated itself — the
/// wipe deadline must not move back.
#[test]
fn switching_to_the_older_session_does_not_pull_the_key_wipe_in() {
    for seed in 0..16u64 {
        let mut p = new_pair(0xC05A_0000 + seed);
        p.b.tunnel.set_endpoint(a_addr());
        let init_a = p.a_initiates();
        let init_b = p.b_initiates();
        // 20 ms each way: the initiations are answered at 20 ms, the
        // handshakes complete at 40 ms, the confirmations arrive at 60 ms.
        p.clock.advance(20 * MS);
        let resp_a = response(p.deliver_to_a(&init_b));
        let resp_b = response(p.deliver_to_b(&init_a));
        let completed = p.clock.advance(20 * MS);
        assert_eq!(p.deliver_to_a(&resp_b).rx, Rx::HandshakeComplete);
        assert_eq!(p.deliver_to_b(&resp_a).rx, Rx::HandshakeComplete);
        let wipe = Some(completed.add_nanos(consts::SESSION_DISCARD_TIME));
        assert_eq!(p.a.tunnel.timer(Timer::ZeroKeyMaterial), wipe);
        assert_eq!(p.b.tunnel.timer(Timer::ZeroKeyMaterial), wipe);

        let keepalive = |polled: Polled| match polled {
            Polled::Transmit(w, SendReason::Keepalive, _) => w,
            other => panic!("{other:?}"),
        };
        let ka_a = keepalive(p.a.poll(completed, &mut p.rng));
        let ka_b = keepalive(p.b.poll(completed, &mut p.rng));
        p.clock.advance(20 * MS);
        let at_b = p.deliver_to_b(&ka_a);
        let at_a = p.deliver_to_a(&ka_b);
        assert_ne!(at_a.session_established, at_b.session_established);
        // One side has switched to a session derived at 20 ms. Neither
        // deadline has moved.
        assert_eq!(
            p.a.tunnel.timer(Timer::ZeroKeyMaterial),
            wipe,
            "seed {seed}"
        );
        assert_eq!(
            p.b.tunnel.timer(Timer::ZeroKeyMaterial),
            wipe,
            "seed {seed}"
        );
    }
}

/// Answering the peer's initiation neither cancels nor delays our own
/// retry: with both first messages lost, ours goes out again on schedule
/// and completes.
#[test]
fn our_retry_still_goes_out_after_answering_the_peers_initiation() {
    let mut p = new_pair(0xC057);
    p.b.tunnel.set_endpoint(a_addr());
    // A initiates at t = 0; the initiation is lost.
    let _lost = p.a_initiates();
    let retry_due = p.a.tunnel.timer(Timer::RetransmitHandshake).unwrap();
    // At t = 2 s B's own initiation arrives and A answers it; that answer
    // is lost as well.
    p.clock.advance(2 * S);
    let init_b = p.b_initiates();
    let _lost = response(p.deliver_to_a(&init_b));
    assert_eq!(
        p.a.tunnel.timer(Timer::RetransmitHandshake),
        Some(retry_due),
        "A's retry is still scheduled for the same instant"
    );
    let now = p.clock.set(retry_due);
    let retry = match p.a.poll(now, &mut p.rng) {
        Polled::Transmit(w, SendReason::HandshakeRetransmit, _) => w,
        other => panic!("{other:?}"),
    };
    let resp_b = response(p.deliver_to_b(&retry));
    let info = p.deliver_to_a(&resp_b);
    assert_eq!(info.rx, Rx::HandshakeComplete);
    assert!(info.session_established);
}

/// Answering an initiation leaves the "previous" session alone: packets
/// the peer still has in flight on it are accepted.
#[test]
fn answering_an_initiation_keeps_the_previous_session() {
    let mut p = new_pair(0xC059);
    p.b.tunnel.set_endpoint(a_addr());
    p.establish();
    // A rekeys. Until A's first packet on the new session reaches B, B
    // keeps sending on the old one, which A now holds as "previous".
    p.clock.advance(6 * S);
    let init_a = p.a_initiates();
    let resp_b = response(p.deliver_to_b(&init_a));
    assert_eq!(p.deliver_to_a(&resp_b).rx, Rx::HandshakeComplete);
    let on_old = p.seal_from_b(b"on the old session");

    // Now B initiates as well, and A answers.
    p.clock.advance(6 * S);
    let init_b = p.b_initiates();
    let _resp_a = response(p.deliver_to_a(&init_b));
    assert_eq!(&p.open_at_a(&on_old)[..18], b"on the old session");
    // The current session is untouched.
    let wire = p.seal_from_a(b"on the current session");
    assert_eq!(index_at(&wire, 4), index_at(&resp_b, 4));
    assert_eq!(&p.open_at_b(&wire)[..10], b"on the cur");
}

/// A handshake we started AFTER answering the peer's is not a crossing:
/// the peer's came first, ours completed later, and the peer will switch
/// to ours on our first packet. So a late packet from the peer on the
/// session we had answered is accepted — and never makes us switch back
/// to it, whatever the indices are. (Switching back left each side
/// responder of the session it sent on: no rekey, a stall when the
/// sessions ran out after three minutes, and a packet lost in the
/// handshake that followed.)
#[test]
fn a_session_we_answered_before_initiating_never_takes_over() {
    for seed in 0..32u64 {
        let mut p = new_pair(0xC058_0000 + seed);
        p.b.tunnel.set_endpoint(a_addr());
        // B initiates and A answers. B completes and sends on that
        // session, but nothing B sends reaches A for now.
        let init_b = p.b_initiates();
        let resp_a = response(p.deliver_to_a(&init_b));
        assert_eq!(p.deliver_to_b(&resp_a).rx, Rx::HandshakeComplete);
        let delayed = p.seal_from_b(b"sent on B's session");
        // A, still without a session it may send on, initiates itself.
        p.clock.advance(6 * S);
        let init_a = p.a_initiates();
        let resp_b = response(p.deliver_to_b(&init_a));
        assert_eq!(p.deliver_to_a(&resp_b).rx, Rx::HandshakeComplete);

        // B's delayed packet is accepted, and A stays on its own session
        // (a transport message names the receiver's index for it).
        let info = p.deliver_to_a(&delayed);
        assert!(matches!(info.rx, Rx::Data(_)), "seed {seed}: {info:?}");
        assert!(
            !info.session_established,
            "seed {seed}: A switched back to the older session"
        );
        let wire = p.seal_from_a(b"from a");
        assert_eq!(index_at(&wire, 4), index_at(&resp_b, 4), "seed {seed}");
        // B switches to it on that packet: both ends use A's session.
        assert!(p.deliver_to_b(&wire).session_established, "seed {seed}");
        let wire = p.seal_from_b(b"from b");
        assert_eq!(index_at(&wire, 4), index_at(&init_a, 4), "seed {seed}");
        assert_eq!(&p.open_at_a(&wire)[..6], b"from b");

        // Five minutes of traffic both ways: never without a session, and
        // every rekey comes from A, the initiator.
        let (mut rekeys_a, mut rekeys_b) = (0, 0);
        for second in 7..=306u64 {
            let now = p.clock.set(Ticks::from_nanos(second * S));
            let wire = p.seal_from_a(b"a to b");
            assert_eq!(&p.open_at_b(&wire)[..6], b"a to b");
            let wire = p.seal_from_b(b"b to a");
            assert_eq!(&p.open_at_a(&wire)[..6], b"b to a");
            let [a, b] = settle(&mut p, now);
            assert!(
                a.iter()
                    .chain(&b)
                    .all(|why| *why == SendReason::HandshakeInitiation),
                "seed {seed} at {second} s"
            );
            rekeys_a += a.len();
            rekeys_b += b.len();
        }
        assert_eq!((rekeys_a, rekeys_b), (2, 0), "seed {seed}");
    }
}

/// A session the peer has been sending on, which we received on without
/// switching to it, is not thrown away the moment the peer initiates
/// again: packets still in flight on it are accepted.
#[test]
fn a_session_the_peer_was_using_survives_its_next_initiation() {
    let mut p = new_pair(0xC05C);
    p.b.tunnel.set_endpoint(a_addr());
    // B initiates, A answers; B completes and sends on that session, but
    // nothing B sends reaches A for now. A then initiates itself.
    let init_b = p.b_initiates();
    let resp_a = response(p.deliver_to_a(&init_b));
    assert_eq!(p.deliver_to_b(&resp_a).rx, Rx::HandshakeComplete);
    let first = p.seal_from_b(b"first");
    p.clock.advance(6 * S);
    let init_a = p.a_initiates();
    let resp_b = response(p.deliver_to_b(&init_a));
    assert_eq!(p.deliver_to_a(&resp_b).rx, Rx::HandshakeComplete);
    // B's first packet arrives: accepted, and A stays on its own session.
    let info = p.deliver_to_a(&first);
    assert!(matches!(info.rx, Rx::Data(_)) && !info.session_established);
    // B, which has not heard from A on A's session yet, sends once more
    // on its own — and then initiates again.
    let second = p.seal_from_b(b"second");
    assert_eq!(index_at(&second, 4), index_at(&first, 4));
    p.clock.advance(6 * S);
    let init_b2 = p.b_initiates();
    let _resp_a2 = response(p.deliver_to_a(&init_b2));
    // The packet that was in flight on the session B had been using.
    assert_eq!(&p.open_at_a(&second)[..6], b"second");
}

/// …but not a dead one. A pending session that has outlived
/// Reject-After-Time — and is only still there because its expiry timer
/// has not been polled yet — must not push a live "previous" session out.
#[test]
fn an_expired_pending_session_does_not_displace_the_previous_one() {
    let mut p = new_pair(0xC05D);
    p.b.tunnel.set_endpoint(a_addr());
    // As above: B's session stays pending at A (used, but not switched
    // to); A's own session, from t = 6 s, is the one both ends use.
    let init_b = p.b_initiates();
    let resp_a = response(p.deliver_to_a(&init_b));
    assert_eq!(p.deliver_to_b(&resp_a).rx, Rx::HandshakeComplete);
    let first = p.seal_from_b(b"first");
    p.clock.advance(6 * S);
    let init_a = p.a_initiates();
    let resp_b = response(p.deliver_to_b(&init_a));
    assert_eq!(p.deliver_to_a(&resp_b).rx, Rx::HandshakeComplete);
    let info = p.deliver_to_a(&first);
    assert!(matches!(info.rx, Rx::Data(_)) && !info.session_established);
    let wire = p.seal_from_a(b"a's session");
    assert!(p.deliver_to_b(&wire).session_established);

    // A packet from B on A's first session, delayed in the network.
    p.clock.set(Ticks::from_nanos(100 * S));
    let delayed = p.seal_from_b(b"delayed");
    // A rekeys at 126 s; its first session becomes "previous".
    let now = p.clock.set(Ticks::from_nanos(126 * S));
    let wire = p.seal_from_a(b"triggers the rekey");
    assert_eq!(&p.open_at_b(&wire)[..8], b"triggers");
    assert_eq!(
        settle(&mut p, now),
        [vec![SendReason::HandshakeInitiation], vec![]]
    );

    // 185 s: the pending session from t = 0 is past Reject-After-Time, but
    // A has not been polled since. B initiates again and A answers.
    p.clock.set(Ticks::from_nanos(185 * S));
    let init_b2 = p.b_initiates();
    let _resp_a2 = response(p.deliver_to_a(&init_b2));
    // A's first session (179 s old) is still good for the delayed packet.
    assert_eq!(&p.open_at_a(&delayed)[..7], b"delayed");
}

/// Only the order of events decides, never their timestamps: a caller
/// whose clock is coarse or stands still — or who handles a batch of
/// datagrams with one clock reading — gets the same decisions. Here the
/// peer is re-created (it has lost every session) and initiates again at
/// the very instant at which our own handshake with its predecessor
/// completed. Its new session is the only one it has, so it must take
/// over on the first packet, whatever the indices are.
#[test]
fn a_peer_that_restarts_in_the_same_instant_takes_over() {
    use wireguard_sans_io::PeerConfig;
    for seed in 0..32u64 {
        let mut p = new_pair(0xC05B_0000 + seed);
        p.b.tunnel.set_endpoint(a_addr());
        // A initiates, B answers, A completes — all at one clock reading.
        let init_a = p.a_initiates();
        let resp_b = response(p.deliver_to_b(&init_a));
        assert_eq!(p.deliver_to_a(&resp_b).rx, Rx::HandshakeComplete);
        // B is re-created and initiates, still at that clock reading.
        let mut cfg = PeerConfig::new(p.a.device.public_key());
        cfg.endpoint = Some(a_addr());
        p.b.tunnel = p.b.device.tunnel(common::id(0), cfg, &mut p.rng).unwrap();
        let init_b = p.b_initiates();
        let resp_a = response(p.deliver_to_a(&init_b));
        assert_eq!(p.deliver_to_b(&resp_a).rx, Rx::HandshakeComplete);
        // B's first packet makes A switch to B's session.
        let wire = p.seal_from_b(b"after the restart");
        let info = p.deliver_to_a(&wire);
        assert!(matches!(info.rx, Rx::Data(_)), "seed {seed}: {info:?}");
        assert!(
            info.session_established,
            "seed {seed}: A kept a session the peer no longer has"
        );
        let wire = p.seal_from_a(b"reply");
        assert_eq!(index_at(&wire, 4), index_at(&init_b, 4), "seed {seed}");
        assert_eq!(&p.open_at_b(&wire)[..5], b"reply");
    }
}

/// A session of ours that is OLDER than the peer's pending one is not a
/// crossed handshake: the peer rekeyed, and its session takes over on the
/// first packet as always — whatever the indices are.
#[test]
fn peer_initiated_rekey_always_takes_over() {
    for seed in 0..32u64 {
        let mut p = new_pair(0xC056_0000 + seed);
        p.b.tunnel.set_endpoint(a_addr());
        p.establish(); // A initiated the current session
        p.clock.advance(30 * S);
        let init_b = p.b_initiates();
        let resp_a = response(p.deliver_to_a(&init_b));
        assert_eq!(p.deliver_to_b(&resp_a).rx, Rx::HandshakeComplete);
        let wire = p.seal_from_b(b"on the new session");
        let info = p.deliver_to_a(&wire);
        assert!(matches!(info.rx, Rx::Data(_)));
        assert!(
            info.session_established,
            "seed {seed}: A must switch to the session B initiated"
        );
        // A now sends on it: the receiver index is B's for the new session.
        let wire = p.seal_from_a(b"reply");
        assert_eq!(index_at(&wire, 4), index_at(&init_b, 4), "seed {seed}");
        assert_eq!(&p.open_at_b(&wire)[..5], b"reply");
    }
}

// ----------------------------------------------------------------------------
// reset(): everything keyed is gone, the endpoint and the replay
// protections stay, and a tunnel with persistent keepalive brings itself
// back up.
// ----------------------------------------------------------------------------
#[test]
fn reset_wipes_sessions_and_keeps_the_endpoint() {
    let mut p = new_pair_with(0xDA, None, Some(25));
    p.establish();
    let old_wire = p.seal_from_b(b"sent before the reset");
    let now = p.clock.advance(6 * S);
    p.a.tunnel.reset();
    assert!(!p.a.is_established(now));
    assert_eq!(p.a.tunnel.endpoint(), Some(b_addr()));
    // Traffic for the old session no longer decrypts.
    assert_eq!(
        p.deliver_to_a(&old_wire).rx,
        Rx::Dropped(DropReason::UnknownIndex)
    );
    // Persistent keepalive: the tunnel re-establishes by itself.
    let init = match p.a.poll(now, &mut p.rng) {
        Polled::Transmit(w, SendReason::HandshakeInitiation, dst) => {
            assert_eq!(dst, b_addr());
            w
        }
        other => panic!("{other:?}"),
    };
    let resp = match p.deliver_to_b(&init).rx {
        Rx::Response(w) => w,
        other => panic!("{other:?}"),
    };
    assert_eq!(p.deliver_to_a(&resp).rx, Rx::HandshakeComplete);
    assert!(matches!(
        p.a.poll(now, &mut p.rng),
        Polled::Transmit(_, SendReason::Keepalive, _)
    ));

    // Without persistent keepalive a reset tunnel is simply quiet.
    let mut q = new_pair(0xDB);
    q.establish();
    q.b.tunnel.reset();
    assert_eq!(q.b.tunnel.next_wake(), None);
    assert_eq!(q.b.poll(q.clock.now(), &mut q.rng), Polled::Idle);
}

// ----------------------------------------------------------------------------
// A keepalive sent by the application (empty payload) is an ordinary
// authenticated message: it answers the peer, but is not "data".
// ----------------------------------------------------------------------------
#[test]
fn explicit_keepalive_answers_the_peer_but_is_not_data() {
    let mut p = new_pair(0xDC);
    p.establish();
    // B owes A a keepalive.
    let wire = p.seal_from_a(b"data");
    let _ = p.open_at_b(&wire);
    assert!(p.b.tunnel.timer(Timer::SendKeepalive).is_some());
    // B sends one explicitly: the debt is settled…
    let ka = p.seal_from_b(b"");
    assert_eq!(ka.len(), consts::KEEPALIVE_LEN);
    assert_eq!(p.b.tunnel.timer(Timer::SendKeepalive), None);
    // …and B does not expect an answer to a keepalive.
    assert_eq!(p.b.tunnel.timer(Timer::NewHandshake), None);
    assert_eq!(p.b.tunnel.stats().tx_keepalives, 1);
    assert_eq!(p.deliver_to_a(&ka).rx, Rx::Keepalive);
    assert_eq!(p.a.tunnel.stats().rx_keepalives, 1);
}

// ----------------------------------------------------------------------------
// is_established() answers for the instant asked about, not for the last
// instant the tunnel happened to be called.
// ----------------------------------------------------------------------------
#[test]
fn is_established_is_evaluated_at_the_given_instant() {
    let mut p = new_pair(0xDD);
    p.establish();
    let t0 = p.clock.now();
    assert!(p.a.is_established(t0));
    // No call has been made since t0, yet:
    assert!(p.a.is_established(Ticks::from_nanos(consts::REJECT_AFTER_TIME - 1)));
    assert!(!p.a.is_established(Ticks::from_nanos(consts::REJECT_AFTER_TIME)));
    assert!(!p.a.is_established(Ticks::from_secs(100_000)));
}
