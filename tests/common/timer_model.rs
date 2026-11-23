//! A reference model of WireGuard's timers.
//!
//! This is a second, deliberately tiny implementation of whitepaper §6,
//! written from the timer rules of the Linux implementation
//! (`drivers/net/wireguard/timers.c`): one function per protocol event,
//! each doing nothing but arming or cancelling timers. It knows nothing
//! about sessions, keys or packets.
//!
//! Tests feed it the events they *observe* through the public API of a
//! [`wireguard_sans_io::Tunnel`] — what the tunnel sent, what it accepted —
//! and compare the model's deadlines with the tunnel's
//! ([`wireguard_sans_io::Tunnel::timer`]) after every step. Any divergence
//! between "what the timers should be" and "what the tunnel armed" shows
//! up as a failed comparison at the exact step that caused it.
//!
//! # What makes it a second opinion
//!
//! * **Its own constants.** The durations below are written out from the
//!   whitepaper's table (§6.1); nothing is imported from the
//!   implementation, so a wrong constant there is a mismatch here.
//! * **Its own rules.** Each function is one function of `timers.c`,
//!   transcribed; where the implementation deliberately does something
//!   else, the model follows it and the difference is listed below, so
//!   that the list — not the model — is where a reader finds out what is
//!   not as in Linux.
//!
//! It is not independent in one respect, and cannot be: it is told what
//! happened by the tunnel under test (it has no packets of its own to
//! parse). What it checks is that the timers are the right function of
//! what happened.
//!
//! # What it covers
//!
//! Six of the tunnel's eight deadlines: the five timers of `timers.c`, and
//! the expiry of a session we answered that the peer has not used
//! (`ExpireNextSession`; the kernel has no timer for that — it checks a
//! keypair's age when the keypair is used). The other two,
//! `SendInitiation` and `FlushKeepalive`, are not timers of the protocol
//! but this implementation's way of doing a thing "as soon as possible"
//! without a work queue; what they must achieve is asserted directly
//! where it matters (initiations are never closer together than
//! Rekey-Timeout; a keepalive that was waiting for a session leaves in
//! the same `poll` sequence in which the session becomes usable).
//!
//! # Where the implementation — and so this model — is not `timers.c`
//!
//! 1. **New-handshake timer: the jitter is drawn per handshake, not per
//!    arming.** `wg_timers_data_sent` adds up to 333 ms of fresh random
//!    jitter to `Keepalive-Timeout + Rekey-Timeout` every time it arms the
//!    timer. The implementation arms the timer in `encapsulate`, which has
//!    no entropy source, so it draws the jitter whenever it makes a
//!    handshake message and uses that value until the next. Two ends that
//!    lose each other at the same instant are separated just the same
//!    (each has its own); the model, which cannot know the value, accepts
//!    any deadline in the 333 ms window.
//! 2. **`timer_need_another_keepalive` is not modelled.** In the kernel,
//!    data that arrives while the keepalive timer is pending sets a flag
//!    that re-arms the timer when it fires. The re-armed timer is
//!    cancelled again as soon as the keepalive it has just queued is sent
//!    (`wg_timers_any_authenticated_packet_sent`), so nothing observable
//!    follows from the flag: against a real kernel, data at 0 s and 5 s
//!    followed by silence produces one keepalive, at 10 s — as here.
//! 3. **Giving up is by time, not by count.** The kernel abandons a
//!    handshake after `MAX_TIMER_HANDSHAKES` (= 90 s / 5 s = 18) retries
//!    have been exceeded — 20 initiations, some 100 s. The implementation
//!    follows the whitepaper's wording (§6.4, "after Rekey-Attempt-Time")
//!    and stops at 90 s: 18 initiations.
//! 4. **Giving up does not arm the key-wipe timer.** The kernel arms it
//!    there if it is not pending. Here it is armed when a session is
//!    established and only then, so after an attempt that never produced
//!    a session there is nothing for it to wipe.
//! 5. **The key-wipe timer counts from the newest *confirmed* session.**
//!    The kernel re-arms it whenever a session is derived, which includes
//!    answering an initiation; a peer that keeps sending initiations it
//!    never completes thereby postpones the wipe of our old keys for as
//!    long as it likes. Here the deadline moves when a session is
//!    confirmed (to that session's creation time + 540 s, never earlier
//!    than it already was).
//! 6. **The key wipe leaves a handshake that is under way alone**, and
//!    cancels the timers of the sessions it wipes. The kernel wipes the
//!    handshake state too — a response that arrives a moment later is
//!    then dropped, and the handshake starts over five seconds on — and
//!    touches no timer. Here an initiation in flight keeps its
//!    retransmission timer, a session we have just answered keeps its
//!    expiry timer, and the keepalive and dead-peer timers (which could
//!    only refer to sessions that no longer exist) are cancelled.
//! 7. **A handshake request that comes too soon is postponed, not
//!    dropped.** `wg_packet_send_queued_handshake_initiation` drops a
//!    request made less than Rekey-Timeout after the last initiation and
//!    relies on a later event to ask again. The implementation remembers
//!    the request and sends the initiation when the pacing allows
//!    (`SendInitiation`). None of the six deadlines modelled here is
//!    affected; the datagrams differ in that case (see the README).
//! 8. **Giving up restarts a persistent keepalive that has already
//!    fired.** The persistent keepalive timer is restarted by every
//!    message sent, and when it fires without a session it only asks for
//!    a handshake. In the kernel the handshake that is then under way
//!    always sends again before it can be abandoned (it gives up by
//!    count), so the timer is always pending at that point. Giving up by
//!    time (difference 3) can happen without a message having been sent
//!    since the timer fired — when nothing ran for longer than
//!    Rekey-Attempt-Time — and would leave a tunnel that is meant to keep
//!    itself up with no timer at all. The interval is started again
//!    there, from the moment of giving up.
#![allow(dead_code, clippy::arithmetic_side_effects)]

use wireguard_sans_io::{Ticks, Timer, Tunnel};

// Whitepaper §6.1, in nanoseconds. Written out here on purpose: see above.
const SECOND: u64 = 1_000_000_000;
/// Rekey-Timeout.
const REKEY_TIMEOUT: u64 = 5 * SECOND;
/// Keepalive-Timeout.
const KEEPALIVE_TIMEOUT: u64 = 10 * SECOND;
/// Reject-After-Time.
const REJECT_AFTER_TIME: u64 = 180 * SECOND;
/// "Rekey-Timeout + jitter": up to a third of a second (the kernel's
/// `REKEY_TIMEOUT_JITTER_MAX_JIFFIES = HZ / 3`).
const REKEY_TIMEOUT_JITTER_MAX: u64 = 333_000_000;
/// How long responses that nothing confirms hold back an initiation of
/// our own, from the first of them (this implementation's bound; the
/// kernel has none).
const UNCONFIRMED_RESPONSE_HOLD: u64 = 3 * REKEY_TIMEOUT;

/// The deadlines, in nanoseconds of the test clock.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TimerModel {
    /// Persistent keepalive interval in nanoseconds, if configured.
    interval: Option<u64>,
    /// `[earliest, latest]`: the tunnel adds up to 333 ms of jitter the
    /// model cannot predict.
    pub retransmit_handshake: Option<(u64, u64)>,
    pub send_keepalive: Option<u64>,
    /// `[earliest, latest]`, as for the retransmission.
    pub new_handshake: Option<(u64, u64)>,
    pub zero_key_material: Option<u64>,
    pub persistent_keepalive: Option<u64>,
    /// When the session we last answered — and the peer has not used —
    /// stops being acceptable.
    pub expire_next_session: Option<u64>,
    /// When we last answered an initiation: the creation time of the
    /// responder-side session that a later confirmation promotes.
    last_response_at: Option<u64>,
    /// When the tunnel last sent an initiation, when it last sent a
    /// response, and when it sent the first of the responses that nothing
    /// has confirmed since (all three survive `reset`: §6.1's pacing is
    /// not something a reset may get around).
    last_initiation_at: Option<u64>,
    last_response_message_at: Option<u64>,
    first_unconfirmed_response_at: Option<u64>,
}

impl TimerModel {
    pub fn new(persistent_keepalive_secs: Option<u16>) -> Self {
        Self {
            interval: persistent_keepalive_secs
                .filter(|s| *s != 0)
                .map(|s| u64::from(s) * 1_000_000_000),
            ..Self::default()
        }
    }

    // ---- timers.c, event by event -------------------------------------

    /// `wg_timers_data_sent`: "Should be called after an authenticated
    /// data packet is sent." Arms new-handshake **if it is not pending**,
    /// for `Keepalive-Timeout + Rekey-Timeout` plus up to 333 ms of jitter
    /// (drawn differently from the kernel: difference 1).
    pub fn data_sent(&mut self, now: u64) {
        if self.new_handshake.is_none() {
            let earliest = now + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT;
            self.new_handshake = Some((earliest, earliest + REKEY_TIMEOUT_JITTER_MAX));
        }
    }

    /// `wg_timers_data_received`: "Should be called after an authenticated
    /// data packet is received." Arms send-keepalive **if it is not
    /// pending**. (The kernel's `else` branch sets a flag with no
    /// observable effect: difference 2.)
    pub fn data_received(&mut self, now: u64) {
        if self.send_keepalive.is_none() {
            self.send_keepalive = Some(now + KEEPALIVE_TIMEOUT);
        }
    }

    /// `wg_timers_any_authenticated_packet_sent`: "…whether keepalive,
    /// data, or handshake." Cancels send-keepalive.
    pub fn any_authenticated_packet_sent(&mut self, now: u64) {
        self.send_keepalive = None;
        self.any_authenticated_packet_traversal(now);
    }

    /// `wg_timers_any_authenticated_packet_received`: "…whether keepalive,
    /// data, or handshake." Cancels new-handshake.
    pub fn any_authenticated_packet_received(&mut self, now: u64) {
        self.new_handshake = None;
        self.any_authenticated_packet_traversal(now);
    }

    /// `wg_timers_any_authenticated_packet_traversal`: restarts the
    /// persistent keepalive interval.
    pub fn any_authenticated_packet_traversal(&mut self, now: u64) {
        if let Some(interval) = self.interval {
            self.persistent_keepalive = Some(now + interval);
        }
    }

    /// `wg_timers_handshake_initiated`: "Should be called after a
    /// handshake initiation message is sent."
    pub fn handshake_initiated(&mut self, now: u64) {
        self.retransmit_handshake = Some((
            now + REKEY_TIMEOUT,
            now + REKEY_TIMEOUT + REKEY_TIMEOUT_JITTER_MAX,
        ));
    }

    /// `wg_timers_handshake_complete`: "Should be called after a handshake
    /// response message is received and processed or when getting key
    /// confirmation via the first data message."
    pub fn handshake_complete(&mut self) {
        self.retransmit_handshake = None;
    }

    /// `wg_timers_session_derived` — called here when a session is
    /// *confirmed*, with the time its keys were derived (difference 5).
    ///
    /// The deadline belongs to the newest session: one that is confirmed
    /// after a newer one already was (crossed handshakes) does not pull it
    /// in. (The kernel's calls come in order of derivation, so there the
    /// last call is the newest.)
    pub fn session_derived(&mut self, created: u64) {
        let deadline = created + 3 * REJECT_AFTER_TIME;
        self.zero_key_material = Some(
            self.zero_key_material
                .map_or(deadline, |armed| armed.max(deadline)),
        );
    }

    // ---- the same, phrased as what a test observes ----------------------

    /// The tunnel emitted a transport message carrying `payload_len`
    /// bytes (0 = keepalive).
    pub fn sent_transport(&mut self, now: u64, payload_len: usize) {
        self.any_authenticated_packet_sent(now);
        if payload_len > 0 {
            self.data_sent(now);
        }
    }

    /// The tunnel emitted a handshake initiation: a `fresh` one, or the
    /// retransmission of one that got no answer.
    ///
    /// §6.1: "under no circumstances will WireGuard send an initiation
    /// message more than once every Rekey-Timeout." This is the property
    /// the tunnel's `SendInitiation` deadline exists to keep (the model
    /// does not predict that deadline — see the module docs — so the
    /// property is checked here, at every initiation any test observes):
    ///
    /// * no two initiations are closer together than Rekey-Timeout;
    /// * a fresh initiation also keeps that distance from the last
    ///   handshake *response* we sent, as in the kernel (which counts both
    ///   in `last_sent_handshake`) — but, unlike the kernel, not for ever:
    ///   responses that nothing confirms (the peer has not used the
    ///   session, no handshake of ours has completed) hold an initiation
    ///   back for at most three Rekey-Timeouts from the first of them. A
    ///   retransmission keeps no distance from a response: an attempt
    ///   that is under way is not held up by having answered the peer in
    ///   the meantime (the kernel drops the retry in that case).
    #[track_caller]
    pub fn sent_initiation(&mut self, now: u64, fresh: bool) {
        if let Some(last) = self.last_initiation_at {
            assert!(
                now >= last + REKEY_TIMEOUT,
                "an initiation (fresh: {fresh}) at {now}, {} ns after the initiation at {last}: \
                 less than Rekey-Timeout",
                now - last
            );
        }
        if let (true, Some(last)) = (fresh, self.last_response_message_at) {
            let held_until = match self.first_unconfirmed_response_at {
                Some(first) => (last + REKEY_TIMEOUT).min(first + UNCONFIRMED_RESPONSE_HOLD),
                None => last + REKEY_TIMEOUT,
            };
            assert!(
                now >= held_until,
                "a fresh initiation at {now}: the response at {last} (first unconfirmed one: \
                 {:?}) holds it until {held_until}",
                self.first_unconfirmed_response_at
            );
        }
        self.last_initiation_at = Some(now);
        self.any_authenticated_packet_sent(now);
        self.handshake_initiated(now);
    }

    /// The tunnel accepted an initiation and emitted the response. The
    /// session this creates is acceptable for Reject-After-Time (§6.2),
    /// used or not.
    pub fn accepted_initiation(&mut self, now: u64) {
        self.any_authenticated_packet_received(now);
        self.any_authenticated_packet_sent(now);
        self.last_response_at = Some(now);
        self.last_response_message_at = Some(now);
        // A run of unconfirmed responses starts here unless one is under
        // way; a run ends with a confirmation, or Reject-After-Time after
        // it began.
        if !self
            .first_unconfirmed_response_at
            .is_some_and(|first| now < first + REJECT_AFTER_TIME)
        {
            self.first_unconfirmed_response_at = Some(now);
        }
        self.expire_next_session = Some(now + REJECT_AFTER_TIME);
    }

    /// The tunnel accepted a response: handshake complete as initiator.
    pub fn accepted_response(&mut self, now: u64) {
        self.first_unconfirmed_response_at = None;
        self.handshake_complete();
        self.session_derived(now);
        self.any_authenticated_packet_received(now);
    }

    /// The tunnel accepted a transport message carrying `payload_len`
    /// bytes. `confirmed` is `Handled::session_established`: this message
    /// was the key confirmation of a responder-side session.
    pub fn accepted_transport(&mut self, now: u64, payload_len: usize, confirmed: bool) {
        if confirmed {
            self.first_unconfirmed_response_at = None;
            self.handshake_complete();
            self.session_derived(self.last_response_at.unwrap_or(now));
            // The pending session is the one in use now: it no longer
            // expires as an unused one.
            self.expire_next_session = None;
        }
        self.any_authenticated_packet_received(now);
        if payload_len > 0 {
            self.data_received(now);
        }
    }

    /// `PollOutput::HandshakeExpired` (`wg_expired_retransmit_handshake`
    /// past the attempt limit): retries stop, and the keepalive we owed is
    /// cancelled (`timer_delete(&peer->timer_send_keepalive)`). The
    /// key-wipe timer is not armed here (difference 4); *when* the tunnel
    /// gives up is its own business (difference 3) — the model is told.
    ///
    /// A persistent keepalive that is not pending at this point starts
    /// its interval again (difference 8).
    pub fn gave_up(&mut self, now: u64) {
        self.retransmit_handshake = None;
        self.send_keepalive = None;
        if let (Some(interval), None) = (self.interval, self.persistent_keepalive) {
            self.persistent_keepalive = Some(now + interval);
        }
    }

    /// `PollOutput::SessionsExpired` (`wg_expired_zero_key_material`),
    /// with difference 6: the timers of the wiped sessions are cancelled;
    /// the retransmission timer of an initiation in flight and the expiry
    /// of a session we have just answered keep running.
    pub fn keys_zeroed(&mut self) {
        self.zero_key_material = None;
        self.send_keepalive = None;
        self.new_handshake = None;
    }

    /// `Tunnel::reset`.
    pub fn reset(&mut self) {
        *self = Self {
            interval: self.interval,
            last_response_at: None,
            last_initiation_at: self.last_initiation_at,
            last_response_message_at: self.last_response_message_at,
            first_unconfirmed_response_at: self.first_unconfirmed_response_at,
            ..Self::default()
        };
    }

    /// The tunnel was polled to `Idle` at `now`: every timer that was due
    /// has fired. (What a firing *does* is observed as the datagrams the
    /// tunnel emits, which arrive as the events above.)
    ///
    /// For a jittered deadline whose window `now` is inside, only the
    /// tunnel knows whether it was due. The retransmission says so itself
    /// (it is a datagram); the new-handshake timer does not always (a
    /// handshake may be under way already), so for it the model looks: it
    /// has fired if the tunnel no longer has it.
    pub fn polled_to_idle(&mut self, now: u64, tunnel: &Tunnel) {
        if self
            .retransmit_handshake
            .is_some_and(|(_, latest)| latest <= now)
        {
            self.retransmit_handshake = None;
        }
        if self.new_handshake.is_some_and(|(earliest, latest)| {
            latest <= now || (earliest <= now && tunnel.timer(Timer::NewHandshake).is_none())
        }) {
            self.new_handshake = None;
        }
        for slot in [
            &mut self.send_keepalive,
            &mut self.zero_key_material,
            &mut self.persistent_keepalive,
            &mut self.expire_next_session,
        ] {
            if slot.is_some_and(|at| at <= now) {
                *slot = None;
            }
        }
    }

    // ---- what no comparison can show ------------------------------------

    /// A tunnel with a persistent keepalive keeps itself up: as long as it
    /// knows where the peer is, it has the next keepalive or a handshake
    /// of its own scheduled — at every moment, whatever has happened.
    ///
    /// The comparison below cannot see a tunnel that has stopped: the
    /// model is told what the tunnel did, and follows it into a state in
    /// which nothing is armed. So this is asserted about the tunnel
    /// directly, wherever the timers are compared.
    #[track_caller]
    fn assert_keeps_itself_up(&self, tunnel: &Tunnel, context: &str) {
        if self.interval.is_none() || tunnel.endpoint().is_none() {
            return;
        }
        let scheduled = [
            Timer::PersistentKeepalive,
            Timer::RetransmitHandshake,
            Timer::SendInitiation,
        ]
        .into_iter()
        .any(|timer| tunnel.timer(timer).is_some());
        assert!(
            scheduled,
            "{context}: a tunnel with a persistent keepalive has neither a keepalive nor a \
             handshake scheduled: it stays down until its application sends\nmodel = {self:?}"
        );
    }

    // ---- comparison -----------------------------------------------------

    /// Assert the tunnel's timers are exactly the model's: the five of
    /// `timers.c` and the expiry of a pending session.
    ///
    /// A deadline at or before `now` is *in transit*: the tunnel fires due
    /// timers one `poll()` call at a time, so between those calls it and
    /// the model may momentarily disagree about a timer that is due. Such
    /// a timer is skipped here; once the tunnel has been polled to `Idle`
    /// (after which the caller asserts it has nothing due, and
    /// [`polled_to_idle`](Self::polled_to_idle) has run) every timer is
    /// compared.
    #[track_caller]
    pub fn assert_matches(&self, tunnel: &Tunnel, now: u64, context: &str) {
        self.assert_keeps_itself_up(tunnel, context);
        let pending = |at: Option<u64>| at.filter(|at| *at > now);
        let got = |t: Timer| pending(tunnel.timer(t).map(Ticks::nanos));
        let exact = [
            ("SendKeepalive", Timer::SendKeepalive, self.send_keepalive),
            (
                "ZeroKeyMaterial",
                Timer::ZeroKeyMaterial,
                self.zero_key_material,
            ),
            (
                "PersistentKeepalive",
                Timer::PersistentKeepalive,
                self.persistent_keepalive,
            ),
            (
                "ExpireNextSession",
                Timer::ExpireNextSession,
                self.expire_next_session,
            ),
        ];
        for (name, timer, expected) in exact {
            let expected = pending(expected);
            assert_eq!(
                got(timer),
                expected,
                "{context}: timer {name}: tunnel has {:?}, reference model has {expected:?}\n\
                 model = {self:?}",
                got(timer)
            );
        }
        let jittered = [
            (
                "RetransmitHandshake",
                Timer::RetransmitHandshake,
                self.retransmit_handshake,
            ),
            ("NewHandshake", Timer::NewHandshake, self.new_handshake),
        ];
        for (name, timer, window) in jittered {
            let expected = window.filter(|(_, latest)| *latest > now);
            match (got(timer), expected) {
                (None, None) => {}
                (Some(at), Some((earliest, latest))) => assert!(
                    (earliest..=latest).contains(&at),
                    "{context}: timer {name}: tunnel has {at}, reference model allows \
                     {earliest}..={latest}"
                ),
                // The jitter window straddles `now`: the tunnel's deadline
                // may already have passed.
                (None, Some((earliest, _))) if earliest <= now => {}
                (tunnel_has, model_has) => panic!(
                    "{context}: timer {name}: tunnel has {tunnel_has:?}, reference model has \
                     {model_has:?}\nmodel = {self:?}"
                ),
            }
        }
    }
}
