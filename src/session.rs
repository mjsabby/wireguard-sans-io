//! A secure session: one keypair derived from one completed handshake,
//! with its counters and replay window (whitepaper §5.4.5, §6.2, §6.3) —
//! and the three places a tunnel keeps sessions in ([`Sessions`]).

use crate::Error;
use crate::consts::{REJECT_AFTER_MESSAGES, REJECT_AFTER_TIME};
use crate::noise::SessionKeys;
use crate::replay::ReplayWindow;
use crate::time::Ticks;

/// One keypair with its counters and replay window. It lives in one cell
/// of the tunnel's [`Sessions`] from the moment its keys are derived until
/// it is wiped there.
///
/// Laid out by hand (see [`crate::Tunnel`]'s definition for why): the
/// first 128 bytes — two cache lines, the tunnel sees to their alignment
/// — hold everything a data packet reads or writes except its one word
/// of the replay bitmap, which follows.
#[repr(C)]
pub(crate) struct Session {
    pub keys: SessionKeys,
    /// Whether transport data may be *sent* on this session. Initiator
    /// sessions are confirmed at creation; responder sessions only once
    /// the first authenticated transport message arrives (whitepaper §5.1:
    /// KEA+C confirmation).
    pub confirmed: bool,
    pub send_counter: u64,
    pub created: Ticks,
    /// Order of creation among this tunnel's sessions (the tunnel counts
    /// them). Which of two sessions is the newer is decided by this, never
    /// by `created`: a caller's clock may be coarse or stand still.
    pub serial: u64,
    /// For a session we answered: the index of the initiation of our own
    /// that was in flight at that moment, if there was one — the two
    /// handshakes crossed.
    pub crossed_with: Option<u32>,
    pub replay: ReplayWindow,
}

impl Session {
    /// A cell that holds no session: no keys, nothing else either.
    const fn blank() -> Self {
        Self {
            keys: SessionKeys::blank(),
            send_counter: 0,
            replay: ReplayWindow::new(),
            created: Ticks::ZERO,
            serial: 0,
            crossed_with: None,
            confirmed: false,
        }
    }

    /// Wipe the keys where they lie and reset everything else, leaving
    /// the cell exactly as [`Session::blank`] makes it.
    fn wipe(&mut self) {
        self.keys.wipe();
        self.send_counter = 0;
        self.replay = ReplayWindow::new();
        self.created = Ticks::ZERO;
        self.serial = 0;
        self.crossed_with = None;
        self.confirmed = false;
    }

    /// Is this cell exactly what [`Session::blank`] makes? (For tests of
    /// the wiping.)
    #[cfg(test)]
    pub(crate) fn is_blank(&self) -> bool {
        self.keys.is_blank()
            && self.send_counter == 0
            && self.created == Ticks::ZERO
            && self.serial == 0
            && self.crossed_with.is_none()
            && !self.confirmed
            && std::format!("{:?}", self.replay) == std::format!("{:?}", ReplayWindow::new())
    }

    #[cfg(test)]
    pub(crate) fn new(mut keys: SessionKeys, created: Ticks) -> Self {
        let mut session = Self::blank();
        session.created = created;
        session.keys.take_from(&mut keys);
        session.confirmed = session.keys.is_initiator;
        session
    }

    /// Age in nanoseconds at `now`.
    pub(crate) fn age(&self, now: Ticks) -> u64 {
        now.since(self.created)
    }

    /// May we encrypt outgoing data on this session right now?
    /// (whitepaper §6.2: Reject-After-Time / Reject-After-Messages, plus
    /// the confirmation rule.)
    pub(crate) fn usable_for_send(&self, now: Ticks) -> bool {
        self.confirmed
            && self.send_counter < REJECT_AFTER_MESSAGES
            && self.age(now) < REJECT_AFTER_TIME
    }

    /// Take the next sending counter; `None` at the reject limit
    /// (whitepaper §6.2: Reject-After-Messages).
    pub(crate) fn next_counter(&mut self) -> Option<u64> {
        if self.send_counter >= REJECT_AFTER_MESSAGES {
            return None;
        }
        let counter = self.send_counter;
        self.send_counter = self.send_counter.checked_add(1)?;
        Some(counter)
    }

    /// The deadline after which this session neither sends nor receives.
    pub(crate) fn rejects_at(&self) -> Ticks {
        self.created.add_nanos(REJECT_AFTER_TIME)
    }
}

/// Which of the three roles of whitepaper §6.3 a session has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Slot {
    Previous,
    Current,
    Next,
}

/// One cell per role.
const CELLS: usize = 3;

/// The sessions of one tunnel: previous, current and next (whitepaper
/// §6.3).
///
/// Session keys exist in exactly two kinds of place, both inside this
/// struct, and are wiped in both:
///
/// * `staged` — where a handshake step derives the keys of a session that
///   does not exist yet. If the step fails they are wiped there.
/// * one of three `cells` — where the keys are copied to (by reference,
///   wiping `staged`) when the step commits, and where they stay until
///   that cell is wiped.
///
/// Rotating the roles — next becomes current, current becomes previous —
/// changes which cell has which role and moves no key. A cell without a
/// role is always blank; none is ever uninitialised, so a `Sessions` that
/// is itself moved carries no stray bytes with it.
///
/// Laid out by hand, like [`Session`]: the roles — which every packet
/// looks up — and the staging area fill the first 128 bytes, and the
/// cells follow.
#[repr(C)]
pub(crate) struct Sessions {
    previous: Option<usize>,
    current: Option<usize>,
    next: Option<usize>,
    staged: SessionKeys,
    cells: [Session; CELLS],
}

impl Sessions {
    /// Where the cells begin (for the test of the tunnel's layout).
    #[cfg(test)]
    pub(crate) const CELLS_OFFSET: usize = core::mem::offset_of!(Self, cells);

    pub(crate) const fn new() -> Self {
        Self {
            cells: [Session::blank(), Session::blank(), Session::blank()],
            staged: SessionKeys::blank(),
            previous: None,
            current: None,
            next: None,
        }
    }

    const fn cell_of(&self, slot: Slot) -> Option<usize> {
        match slot {
            Slot::Previous => self.previous,
            Slot::Current => self.current,
            Slot::Next => self.next,
        }
    }

    pub(crate) fn get(&self, slot: Slot) -> Option<&Session> {
        self.cells.get(self.cell_of(slot)?)
    }

    pub(crate) fn get_mut(&mut self, slot: Slot) -> Option<&mut Session> {
        let cell = self.cell_of(slot)?;
        self.cells.get_mut(cell)
    }

    pub(crate) fn current(&self) -> Option<&Session> {
        self.get(Slot::Current)
    }

    pub(crate) fn next(&self) -> Option<&Session> {
        self.get(Slot::Next)
    }

    /// Which slot holds the session with this local index, if any.
    pub(crate) fn find(&self, local_index: u32) -> Option<Slot> {
        [Slot::Next, Slot::Current, Slot::Previous]
            .into_iter()
            .find(|slot| {
                self.get(*slot)
                    .is_some_and(|s| s.keys.local_index == local_index)
            })
    }

    /// The local index of the session in each slot.
    pub(crate) fn local_indices(&self) -> [Option<u32>; CELLS] {
        [Slot::Previous, Slot::Current, Slot::Next]
            .map(|slot| self.get(slot).map(|s| s.keys.local_index))
    }

    /// Where a handshake step derives the keys of a new session. Blank
    /// when handed out; the step either commits it
    /// ([`install_next`](Self::install_next) /
    /// [`install_current`](Self::install_current)) or leaves it wiped
    /// ([`discard_staged`](Self::discard_staged)).
    pub(crate) fn staging(&mut self) -> &mut SessionKeys {
        self.staged.wipe();
        &mut self.staged
    }

    /// Wipe keys that were staged and are not going to be used.
    pub(crate) fn discard_staged(&mut self) {
        self.staged.wipe();
    }

    /// Wipe the session in a cell, where it lies.
    fn wipe_cell(&mut self, cell: Option<usize>) {
        if let Some(cell) = cell.and_then(|i| self.cells.get_mut(i)) {
            cell.wipe();
        }
    }

    /// A cell that has no role.
    fn free_cell(&self) -> Option<usize> {
        (0..CELLS).find(|i| {
            let i = Some(*i);
            i != self.previous && i != self.current && i != self.next
        })
    }

    /// Make a session out of the staged keys in a free cell. Returns the
    /// cell.
    fn write(
        &mut self,
        created: Ticks,
        serial: u64,
        crossed_with: Option<u32>,
    ) -> Result<usize, Error> {
        // There is always a free cell: the callers give up a role first.
        let free = self.free_cell();
        let Some((free, session)) = free.and_then(|i| Some((i, self.cells.get_mut(i)?))) else {
            self.staged.wipe();
            return Err(Error::Internal);
        };
        session.wipe();
        session.keys.take_from(&mut self.staged);
        session.created = created;
        session.confirmed = session.keys.is_initiator;
        session.serial = serial;
        session.crossed_with = crossed_with;
        Ok(free)
    }

    /// The staged keys are those of a session we answered: it becomes
    /// `next`.
    ///
    /// The session it replaces there was normally never used and is wiped.
    /// One the peer has sent on — which we received on without switching
    /// to it — may still have the peer's packets in flight: it steps down
    /// to `previous` instead (unless it has outlived Reject-After-Time
    /// and only its expiry timer has not been polled yet), and the
    /// session that was there is wiped.
    pub(crate) fn install_next(
        &mut self,
        now: Ticks,
        serial: u64,
        crossed_with: Option<u32>,
    ) -> Result<(), Error> {
        if let Some(old) = self.next.take() {
            let in_use = self
                .cells
                .get(old)
                .is_some_and(|s| s.confirmed && s.age(now) < REJECT_AFTER_TIME);
            if in_use {
                let stale = self.previous.replace(old);
                self.wipe_cell(stale);
            } else {
                self.wipe_cell(Some(old));
            }
        }
        self.next = Some(self.write(now, serial, crossed_with)?);
        Ok(())
    }

    /// The staged keys are those of a session we initiated: it becomes
    /// `current`, the session that was current steps down to `previous`,
    /// and the one that was there is wiped. `next` is left alone.
    pub(crate) fn install_current(&mut self, now: Ticks, serial: u64) -> Result<(), Error> {
        let stale = core::mem::replace(&mut self.previous, self.current.take());
        self.wipe_cell(stale);
        self.current = Some(self.write(now, serial, None)?);
        Ok(())
    }

    /// §6.3, on the first packet of a session we answered: next becomes
    /// current, current becomes previous, and the session that was there
    /// is wiped.
    pub(crate) fn promote_next(&mut self) {
        let stale = core::mem::replace(&mut self.previous, self.current.take());
        self.wipe_cell(stale);
        self.current = self.next.take();
    }

    /// Exchange the roles of `current` and `previous` (the tunnel goes
    /// back to a session it had stepped down from). No key moves.
    pub(crate) fn swap_current_and_previous(&mut self) {
        core::mem::swap(&mut self.current, &mut self.previous);
    }

    /// Wipe the session in `slot`.
    pub(crate) fn discard(&mut self, slot: Slot) {
        let cell = match slot {
            Slot::Previous => self.previous.take(),
            Slot::Current => self.current.take(),
            Slot::Next => self.next.take(),
        };
        self.wipe_cell(cell);
    }

    /// Test support — the memory invariant: is there key material
    /// anywhere but in the cells that have a role?
    #[cfg(test)]
    pub(crate) fn has_stray_keys(&self) -> bool {
        let with_role = [self.previous, self.current, self.next];
        let stray_cell = self
            .cells
            .iter()
            .enumerate()
            .any(|(i, cell)| !with_role.contains(&Some(i)) && !cell.is_blank());
        stray_cell || !self.staged.is_blank()
    }

    /// Test support: no session in any role, and not one key byte left.
    #[cfg(test)]
    pub(crate) fn is_wiped(&self) -> bool {
        self.previous.is_none()
            && self.current.is_none()
            && self.next.is_none()
            && !self.has_stray_keys()
    }
}

impl core::fmt::Debug for Sessions {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sessions")
            .field("previous", &self.get(Slot::Previous))
            .field("current", &self.get(Slot::Current))
            .field("next", &self.get(Slot::Next))
            .finish()
    }
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Session(local={}, peer={}, initiator={}, confirmed={}, sent={})",
            self.keys.local_index,
            self.keys.peer_index,
            self.keys.is_initiator,
            self.confirmed,
            self.send_counter
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        clippy::unwrap_used
    )]
    use super::*;
    use crate::noise::SessionKeys;
    use std::vec::Vec;

    fn keys(initiator: bool) -> SessionKeys {
        SessionKeys {
            send: [1; 32],
            recv: [2; 32],
            local_index: 10,
            peer_index: 20,
            is_initiator: initiator,
        }
    }

    #[test]
    fn confirmation_rules() {
        let now = Ticks::from_secs(5);
        let s = Session::new(keys(true), now);
        assert!(s.confirmed && s.usable_for_send(now));
        let s = Session::new(keys(false), now);
        assert!(!s.confirmed && !s.usable_for_send(now));
    }

    #[test]
    fn reject_after_time() {
        let born = Ticks::from_secs(100);
        let s = Session::new(keys(true), born);
        assert!(s.usable_for_send(born.add_nanos(REJECT_AFTER_TIME - 1)));
        assert!(!s.usable_for_send(born.add_nanos(REJECT_AFTER_TIME)));
        assert_eq!(s.rejects_at(), born.add_nanos(REJECT_AFTER_TIME));
    }

    #[test]
    fn counter_exhaustion() {
        let mut s = Session::new(keys(true), Ticks::ZERO);
        s.send_counter = REJECT_AFTER_MESSAGES - 1;
        assert_eq!(s.next_counter(), Some(REJECT_AFTER_MESSAGES - 1));
        assert_eq!(s.next_counter(), None);
        assert_eq!(s.next_counter(), None, "stays refused");
        assert!(!s.usable_for_send(Ticks::ZERO));
    }

    // ---- the three slots, and what is left in memory -------------------

    /// Stage the keys of session number `n`: every key byte is `n` (send)
    /// or `n + 100` (receive), so a stray copy is recognisable.
    fn stage(s: &mut Sessions, n: u8, initiator: bool) {
        let k = s.staging();
        assert!(k.is_blank(), "the staging area is handed out blank");
        k.send = [n; 32];
        k.recv = [n + 100; 32];
        k.local_index = u32::from(n);
        k.peer_index = 1000 + u32::from(n);
        k.is_initiator = initiator;
    }

    /// The session number in each role: previous, current, next.
    fn roles(s: &Sessions) -> [Option<u8>; 3] {
        [Slot::Previous, Slot::Current, Slot::Next].map(|slot| {
            s.get(slot).map(|session| {
                let n = session.keys.send[0];
                assert_eq!(session.keys.send, [n; 32]);
                assert_eq!(session.keys.recv, [n + 100; 32]);
                assert_eq!(session.keys.local_index, u32::from(n));
                n
            })
        })
    }

    /// The memory invariant: session keys are in the cells that have a
    /// role and nowhere else in the struct.
    #[track_caller]
    fn assert_no_stray_keys(s: &Sessions) {
        assert!(
            !s.has_stray_keys(),
            "key material outside the cells that have a role: {s:?}"
        );
        // No cell has two roles.
        let used: Vec<usize> = [s.previous, s.current, s.next]
            .into_iter()
            .flatten()
            .collect();
        let mut distinct = used.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(used.len(), distinct.len(), "one cell in two roles");
    }

    fn at(secs: u64) -> Ticks {
        Ticks::from_secs(secs)
    }

    #[test]
    fn a_new_tunnel_holds_nothing() {
        let s = Sessions::new();
        assert_eq!(roles(&s), [None, None, None]);
        assert!(s.cells.iter().all(Session::is_blank));
        assert!(s.is_wiped());
        assert_no_stray_keys(&s);
    }

    #[test]
    fn sessions_we_initiate_rotate_and_the_oldest_is_wiped() {
        let mut s = Sessions::new();
        stage(&mut s, 1, true);
        s.install_current(at(0), 1).unwrap();
        assert_eq!(roles(&s), [None, Some(1), None]);
        assert_no_stray_keys(&s);
        assert!(s.current().unwrap().confirmed, "initiator: usable at once");

        stage(&mut s, 2, true);
        s.install_current(at(10), 2).unwrap();
        assert_eq!(roles(&s), [Some(1), Some(2), None]);
        assert_no_stray_keys(&s);

        stage(&mut s, 3, true);
        s.install_current(at(20), 3).unwrap();
        assert_eq!(roles(&s), [Some(2), Some(3), None]);
        // Session 1 is gone from every byte of the struct.
        assert_no_stray_keys(&s);
        assert_eq!(s.get(Slot::Current).unwrap().created, at(20));
        assert_eq!(s.get(Slot::Current).unwrap().serial, 3);
    }

    #[test]
    fn a_session_we_answered_waits_in_next_and_takes_over_in_place() {
        let mut s = Sessions::new();
        stage(&mut s, 1, true);
        s.install_current(at(0), 1).unwrap();
        stage(&mut s, 2, true);
        s.install_current(at(1), 2).unwrap();
        stage(&mut s, 3, false);
        s.install_next(at(2), 3, Some(77)).unwrap();
        assert_eq!(roles(&s), [Some(1), Some(2), Some(3)]);
        assert_no_stray_keys(&s);
        let next = s.next().unwrap();
        assert!(!next.confirmed, "responder: not usable until confirmed");
        assert_eq!(next.crossed_with, Some(77));

        // Promotion changes roles; no key moves, and the session that
        // drops out (1) is wiped where it was.
        let cell_of_3 = s.next.unwrap();
        s.promote_next();
        assert_eq!(roles(&s), [Some(2), Some(3), None]);
        assert_eq!(s.current, Some(cell_of_3), "promoted in place");
        assert_no_stray_keys(&s);
    }

    #[test]
    fn answering_again_replaces_a_pending_session_that_was_never_used() {
        let mut s = Sessions::new();
        stage(&mut s, 1, true);
        s.install_current(at(0), 1).unwrap();
        stage(&mut s, 2, false);
        s.install_next(at(1), 2, None).unwrap();
        stage(&mut s, 3, false);
        s.install_next(at(2), 3, None).unwrap();
        // 2 was never confirmed: wiped, and nothing else disturbed.
        assert_eq!(roles(&s), [None, Some(1), Some(3)]);
        assert_no_stray_keys(&s);
    }

    #[test]
    fn answering_again_keeps_a_pending_session_the_peer_has_used() {
        let mut s = Sessions::new();
        stage(&mut s, 1, true);
        s.install_current(at(0), 1).unwrap();
        stage(&mut s, 2, true);
        s.install_current(at(1), 2).unwrap();
        stage(&mut s, 3, false);
        s.install_next(at(2), 3, None).unwrap();
        s.get_mut(Slot::Next).unwrap().confirmed = true;
        stage(&mut s, 4, false);
        s.install_next(at(3), 4, None).unwrap();
        // 3 steps down to previous; 1, which was there, is wiped.
        assert_eq!(roles(&s), [Some(3), Some(2), Some(4)]);
        assert_no_stray_keys(&s);

        // …unless it has outlived Reject-After-Time: then it is wiped and
        // the previous session stays.
        s.get_mut(Slot::Next).unwrap().confirmed = true;
        stage(&mut s, 5, false);
        s.install_next(at(3).add_nanos(REJECT_AFTER_TIME), 5, None)
            .unwrap();
        assert_eq!(roles(&s), [Some(3), Some(2), Some(5)]);
        assert_no_stray_keys(&s);
        // One nanosecond earlier it would still have counted as in use.
        let mut s2 = Sessions::new();
        stage(&mut s2, 1, false);
        s2.install_next(at(3), 1, None).unwrap();
        s2.get_mut(Slot::Next).unwrap().confirmed = true;
        stage(&mut s2, 2, false);
        s2.install_next(at(3).add_nanos(REJECT_AFTER_TIME - 1), 2, None)
            .unwrap();
        assert_eq!(roles(&s2), [Some(1), None, Some(2)]);
        assert_no_stray_keys(&s2);
    }

    #[test]
    fn swapping_current_and_previous_moves_no_key() {
        let mut s = Sessions::new();
        stage(&mut s, 1, true);
        s.install_current(at(0), 1).unwrap();
        stage(&mut s, 2, true);
        s.install_current(at(1), 2).unwrap();
        let (cell_1, cell_2) = (s.previous, s.current);
        s.swap_current_and_previous();
        assert_eq!(roles(&s), [Some(2), Some(1), None]);
        assert_eq!((s.current, s.previous), (cell_1, cell_2));
        assert_no_stray_keys(&s);
        // With only one of the two present the roles still swap.
        s.discard(Slot::Previous);
        s.swap_current_and_previous();
        assert_eq!(roles(&s), [Some(1), None, None]);
        assert_no_stray_keys(&s);
    }

    #[test]
    fn discarding_a_slot_wipes_its_cell() {
        for slot in [Slot::Previous, Slot::Current, Slot::Next] {
            let mut s = Sessions::new();
            stage(&mut s, 1, true);
            s.install_current(at(0), 1).unwrap();
            stage(&mut s, 2, true);
            s.install_current(at(1), 2).unwrap();
            stage(&mut s, 3, false);
            s.install_next(at(2), 3, None).unwrap();
            let cell = s.cell_of(slot).unwrap();
            s.discard(slot);
            assert!(s.get(slot).is_none());
            assert!(s.cells[cell].is_blank(), "{slot:?} was not wiped");
            assert_no_stray_keys(&s);
            assert_eq!(roles(&s).iter().flatten().count(), 2);
            // Discarding an empty slot does nothing.
            s.discard(slot);
            assert_no_stray_keys(&s);
            assert_eq!(roles(&s).iter().flatten().count(), 2);
        }
    }

    #[test]
    fn staged_keys_that_are_not_installed_are_wiped() {
        let mut s = Sessions::new();
        stage(&mut s, 9, true);
        assert!(!s.staged.is_blank());
        s.discard_staged();
        assert_no_stray_keys(&s);
        // Staging again hands out a blank area even if the last user left
        // something behind.
        s.staged.send = [0xff; 32];
        assert!(s.staging().is_blank());
    }

    #[test]
    fn sessions_are_found_by_index() {
        let mut s = Sessions::new();
        assert_eq!(s.find(0), None, "a blank cell is not a session");
        stage(&mut s, 1, true);
        s.install_current(at(0), 1).unwrap();
        stage(&mut s, 2, true);
        s.install_current(at(1), 2).unwrap();
        stage(&mut s, 3, false);
        s.install_next(at(2), 3, None).unwrap();
        assert_eq!(s.find(1), Some(Slot::Previous));
        assert_eq!(s.find(2), Some(Slot::Current));
        assert_eq!(s.find(3), Some(Slot::Next));
        assert_eq!(s.find(4), None);
        assert_eq!(s.find(0), None);
        assert_eq!(s.local_indices(), [Some(1), Some(2), Some(3)]);
        s.discard(Slot::Current);
        assert_eq!(s.find(2), None);
        assert_eq!(s.local_indices(), [Some(1), None, Some(3)]);
    }

    /// The rotation against a three-variable model of whitepaper §6.3,
    /// over random operation sequences, with the memory invariant checked
    /// after every step.
    #[test]
    fn random_rotations_match_the_model_and_leave_no_stray_keys() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next_random = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..200 {
            let mut s = Sessions::new();
            // The model: which session number has which role.
            let (mut previous, mut current, mut next): (Option<u8>, Option<u8>, Option<u8>) =
                (None, None, None);
            let mut next_confirmed = false;
            let mut n = 0u8;
            for step in 0..60u64 {
                let now = at(step);
                match next_random() % 7 {
                    0 | 1 => {
                        n += 1;
                        stage(&mut s, n, true);
                        s.install_current(now, u64::from(n)).unwrap();
                        previous = current;
                        current = Some(n);
                    }
                    2 | 3 => {
                        n += 1;
                        stage(&mut s, n, false);
                        s.install_next(now, u64::from(n), None).unwrap();
                        if next.is_some() && next_confirmed {
                            previous = next;
                        }
                        next = Some(n);
                        next_confirmed = false;
                    }
                    4 => {
                        if next.is_some() {
                            s.promote_next();
                            previous = current;
                            current = next.take();
                            next_confirmed = false;
                        }
                    }
                    5 => {
                        if let Some(session) = s.get_mut(Slot::Next) {
                            session.confirmed = true;
                            next_confirmed = true;
                        }
                    }
                    _ => {
                        let slot = [Slot::Previous, Slot::Current, Slot::Next]
                            [(next_random() % 3) as usize];
                        s.discard(slot);
                        match slot {
                            Slot::Previous => previous = None,
                            Slot::Current => current = None,
                            Slot::Next => {
                                next = None;
                                next_confirmed = false;
                            }
                        }
                    }
                }
                assert_eq!(roles(&s), [previous, current, next], "step {step}");
                assert_no_stray_keys(&s);
            }
        }
    }
}
