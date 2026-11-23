//! The timer table for whitepaper §6: one armed deadline per timer, and
//! nothing else.
//!
//! WireGuard's timer behaviour is specified as five timers that protocol
//! events arm and cancel (§6.1–§6.5; the Linux implementation's
//! `timers.c` is the same five). This module keeps exactly that — a table
//! of `Option<Ticks>` deadlines — plus three deadlines of its own for work
//! that an implementation with a packet queue and a worker thread would
//! hand to those (see [`Timer`]). Where the behaviour deliberately differs
//! from Linux is listed in the README ("Protocol notes") and, with the
//! kernel functions named, in `tests/common/timer_model.rs`.
//!
//! * An event *arms* a timer (records when it will fire) or *clears* it.
//! * [`crate::Tunnel::next_wake`] is the minimum of the table.
//! * [`crate::Tunnel::poll`] takes the timers whose deadline has passed,
//!   one at a time, and runs their handlers.
//!
//! Because both functions read the same table, they cannot disagree: after
//! `poll` reports `Idle`, every armed deadline is strictly in the future.
//! And because a timer is a deadline rather than a condition re-evaluated
//! from "time since the last packet", it fires once per arming, measured
//! from the event that armed it — the *first* unanswered packet, as the
//! whitepaper specifies, not the most recent one.

use crate::time::Ticks;

/// One of a [`crate::Tunnel`]'s deadlines.
///
/// The first five are the timers of whitepaper §6 (and of the Linux
/// implementation). The last three are deadlines this implementation
/// needs because it has no packet queue and no background worker:
/// `SendInitiation` and `FlushKeepalive` stand for "as soon as possible"
/// (a handshake that is wanted, once the pacing of §6.1 allows it; a
/// keepalive that is owed, once a session is usable), and
/// `ExpireNextSession` for a check Linux makes lazily, when a keypair is
/// used. They add no protocol rule of their own — but one of them makes a
/// visible difference to Linux: a handshake request that comes too soon
/// after the last initiation is *postponed* to the pacing deadline here,
/// where Linux drops it and waits for a later event to ask again.
///
/// Read a tunnel's deadlines with [`crate::Tunnel::timer`] — for
/// diagnostics ("what is this tunnel waiting for?") and for testing the
/// timer behaviour against a reference model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Timer {
    /// §6.4 — an initiation is in flight; if no response arrives by the
    /// deadline (`Rekey-Timeout` plus up to 333 ms of jitter) it is
    /// retransmitted with a fresh ephemeral, until `Rekey-Attempt-Time`
    /// has passed.
    ///
    /// *Armed* when an initiation is sent. *Cleared* when the handshake
    /// completes, or the attempt is given up.
    RetransmitHandshake,
    /// §6.5 — we received transport data and have sent nothing since; at
    /// the deadline (`Keepalive-Timeout` after the first such packet) a
    /// keepalive goes out so the peer knows we are alive.
    ///
    /// *Armed* when data arrives and the timer is not already running.
    /// *Cleared* when we send any authenticated message.
    SendKeepalive,
    /// §6.5 — we sent transport data and have heard nothing since; at the
    /// deadline (`Keepalive-Timeout + Rekey-Timeout` after the first such
    /// packet) the session is presumed dead and a new handshake starts.
    ///
    /// *Armed* when data is sent and the timer is not already running.
    /// *Cleared* when any authenticated message arrives, including a
    /// handshake message.
    NewHandshake,
    /// §6.3 — no new session for `3 × Reject-After-Time`: the keys of
    /// every session that was in use are wiped. A handshake under way at
    /// that moment is left to finish (see
    /// [`crate::PollOutput::SessionsExpired`]).
    ///
    /// *Armed* whenever a session is established, for `3 ×
    /// Reject-After-Time` after that session's keys were derived; it only
    /// ever moves later.
    ZeroKeyMaterial,
    /// The configured persistent keepalive interval has passed with no
    /// authenticated message in either direction.
    ///
    /// *Re-armed* whenever an authenticated message is sent or received —
    /// and, if it has fired since, when a handshake attempt is given up,
    /// so that a tunnel with a persistent keepalive always has either
    /// this timer or a handshake of its own pending.
    PersistentKeepalive,
    /// A handshake is wanted and will be initiated at the deadline — the
    /// instant the once-per-`Rekey-Timeout` pacing (§6.1) allows it.
    SendInitiation,
    /// A keepalive is waiting for a usable session (the confirmation an
    /// initiator sends right after a handshake, or a keepalive that came
    /// due while a handshake was still running).
    FlushKeepalive,
    /// A session we answered and have not switched to is wiped at its
    /// `Reject-After-Time` — whether the peer never used it, or used it
    /// while we kept sending on a session of our own (crossed handshakes).
    ///
    /// *Armed* when an initiation is answered. *Cleared* when that session
    /// becomes the current one.
    ExpireNextSession,
}

/// Number of timers.
const COUNT: usize = 8;

impl Timer {
    /// Every timer, in the order [`crate::Tunnel::poll`] services timers
    /// that are due at the same call: wipes first, then the handshake
    /// machinery, then keepalives.
    pub const ALL: [Self; COUNT] = [
        Self::ZeroKeyMaterial,
        Self::ExpireNextSession,
        Self::RetransmitHandshake,
        Self::NewHandshake,
        Self::SendInitiation,
        Self::FlushKeepalive,
        Self::SendKeepalive,
        Self::PersistentKeepalive,
    ];

    const fn slot(self) -> usize {
        match self {
            Self::RetransmitHandshake => 0,
            Self::SendKeepalive => 1,
            Self::NewHandshake => 2,
            Self::ZeroKeyMaterial => 3,
            Self::PersistentKeepalive => 4,
            Self::SendInitiation => 5,
            Self::FlushKeepalive => 6,
            Self::ExpireNextSession => 7,
        }
    }
}

/// The armed deadlines of one tunnel.
#[derive(Debug, Clone, Default)]
pub(crate) struct TimerTable {
    deadlines: [Option<Ticks>; COUNT],
}

impl TimerTable {
    /// No timer armed.
    pub(crate) const fn new() -> Self {
        Self {
            deadlines: [None; COUNT],
        }
    }

    /// Arm `timer` to fire at `at`, replacing any earlier deadline.
    pub(crate) fn arm(&mut self, timer: Timer, at: Ticks) {
        if let Some(slot) = self.deadlines.get_mut(timer.slot()) {
            *slot = Some(at);
        }
    }

    /// Arm `timer` to fire at `at` unless it is already running.
    pub(crate) fn arm_if_idle(&mut self, timer: Timer, at: Ticks) {
        if !self.is_armed(timer) {
            self.arm(timer, at);
        }
    }

    /// Cancel `timer`.
    pub(crate) fn clear(&mut self, timer: Timer) {
        if let Some(slot) = self.deadlines.get_mut(timer.slot()) {
            *slot = None;
        }
    }

    /// Cancel every timer.
    pub(crate) fn clear_all(&mut self) {
        self.deadlines = [None; COUNT];
    }

    /// The deadline of `timer`, if armed.
    pub(crate) fn get(&self, timer: Timer) -> Option<Ticks> {
        self.deadlines.get(timer.slot()).copied().flatten()
    }

    pub(crate) fn is_armed(&self, timer: Timer) -> bool {
        self.get(timer).is_some()
    }

    /// The earliest armed deadline.
    pub(crate) fn next_wake(&self) -> Option<Ticks> {
        self.deadlines.iter().flatten().copied().min()
    }

    /// Remove and return a timer whose deadline is at or before `now`,
    /// with that deadline. When several are due, [`Timer::ALL`] decides
    /// the order.
    pub(crate) fn take_due(&mut self, now: Ticks) -> Option<(Timer, Ticks)> {
        for timer in Timer::ALL {
            if let Some(deadline) = self.get(timer) {
                if deadline <= now {
                    self.clear(timer);
                    return Some((timer, deadline));
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use std::collections::HashSet;
    use std::vec::Vec;

    #[test]
    fn every_timer_has_its_own_slot_and_is_listed_once() {
        let slots: HashSet<usize> = Timer::ALL.iter().map(|t| t.slot()).collect();
        assert_eq!(slots.len(), COUNT);
        assert!(slots.iter().all(|&s| s < COUNT));
        let names: HashSet<Timer> = Timer::ALL.iter().copied().collect();
        assert_eq!(names.len(), COUNT);
    }

    #[test]
    fn arm_clear_and_query() {
        let mut t = TimerTable::default();
        assert_eq!(t.next_wake(), None);
        assert!(!t.is_armed(Timer::SendKeepalive));

        t.arm(Timer::SendKeepalive, Ticks::from_secs(10));
        assert_eq!(t.get(Timer::SendKeepalive), Some(Ticks::from_secs(10)));
        assert_eq!(t.get(Timer::NewHandshake), None);
        assert_eq!(t.next_wake(), Some(Ticks::from_secs(10)));

        // arm_if_idle keeps the running deadline; arm replaces it.
        t.arm_if_idle(Timer::SendKeepalive, Ticks::from_secs(99));
        assert_eq!(t.get(Timer::SendKeepalive), Some(Ticks::from_secs(10)));
        t.arm_if_idle(Timer::NewHandshake, Ticks::from_secs(15));
        assert_eq!(t.get(Timer::NewHandshake), Some(Ticks::from_secs(15)));
        t.arm(Timer::SendKeepalive, Ticks::from_secs(20));
        assert_eq!(t.get(Timer::SendKeepalive), Some(Ticks::from_secs(20)));
        assert_eq!(t.next_wake(), Some(Ticks::from_secs(15)));

        t.clear(Timer::NewHandshake);
        assert_eq!(t.next_wake(), Some(Ticks::from_secs(20)));
        t.clear(Timer::NewHandshake); // clearing an idle timer is a no-op
        t.clear_all();
        assert_eq!(t.next_wake(), None);
    }

    #[test]
    fn take_due_fires_each_timer_once_and_only_when_due() {
        let mut t = TimerTable::default();
        t.arm(Timer::SendKeepalive, Ticks::from_secs(10));
        t.arm(Timer::NewHandshake, Ticks::from_secs(15));

        // Strictly before the earliest deadline: nothing.
        assert_eq!(t.take_due(Ticks::from_nanos(10_000_000_000 - 1)), None);
        // Exactly at it: that timer, once.
        assert_eq!(
            t.take_due(Ticks::from_secs(10)),
            Some((Timer::SendKeepalive, Ticks::from_secs(10)))
        );
        assert_eq!(t.take_due(Ticks::from_secs(10)), None);
        assert!(!t.is_armed(Timer::SendKeepalive));
        // The other is untouched until its own deadline.
        assert_eq!(t.next_wake(), Some(Ticks::from_secs(15)));
        assert_eq!(
            t.take_due(Ticks::from_secs(100)),
            Some((Timer::NewHandshake, Ticks::from_secs(15)))
        );
        assert_eq!(t.next_wake(), None);
    }

    #[test]
    fn simultaneously_due_timers_come_out_in_service_order() {
        let mut t = TimerTable::default();
        // Arm everything, deliberately in the opposite order and with
        // deadlines that would sort the other way round.
        for (i, timer) in Timer::ALL.iter().rev().enumerate() {
            t.arm(*timer, Ticks::from_secs(i as u64));
        }
        let mut order = Vec::new();
        while let Some((timer, _)) = t.take_due(Ticks::from_secs(1000)) {
            order.push(timer);
        }
        assert_eq!(order, Timer::ALL.to_vec());
    }

    /// The property the table exists for: once nothing is due, the next
    /// wake-up is strictly in the future.
    #[test]
    fn after_draining_next_wake_is_strictly_future() {
        let mut t = TimerTable::default();
        for (i, timer) in Timer::ALL.iter().enumerate() {
            t.arm(*timer, Ticks::from_secs(3 * i as u64));
        }
        for now in [0u64, 4, 9, 9, 30] {
            let now = Ticks::from_secs(now);
            while t.take_due(now).is_some() {}
            assert!(t.next_wake().is_none_or(|w| w > now));
        }
    }
}
