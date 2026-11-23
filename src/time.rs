//! Caller-supplied time, sans-I/O style.
//!
//! The library never reads a clock. Every API call that depends on time
//! takes one monotonic instant, [`Ticks`], which drives every whitepaper §6
//! timer.
//!
//! The only use WireGuard has for the wall clock is the TAI64N timestamp
//! inside a handshake initiation ([`Tai64N`]), and all the protocol needs
//! from it is that it keeps increasing. So the wall clock is read **once**,
//! as a [`WallClock`] anchor ("at monotonic instant X the Unix clock said
//! Y"), and every later timestamp is derived from the monotonic clock. A
//! wall-clock step during a run therefore cannot make timestamps go
//! backwards.

use core::fmt;

/// A monotonic instant in nanoseconds since an arbitrary caller-chosen
/// epoch (e.g. `std::time::Instant` elapsed-since-start).
///
/// `Ticks` must never decrease across calls into the same
/// [`crate::Tunnel`], and must stay below [`Ticks::MAX`]. All arithmetic is
/// saturating, so even a hostile clock cannot cause a panic — an instant
/// that is earlier than the last one, or out of range, merely stops time
/// for that call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct Ticks(u64);

impl Ticks {
    /// The zero instant.
    pub const ZERO: Self = Self(0);

    /// The latest instant the library takes for a time: 2⁶³ − 1 ns, some
    /// 292 years after the caller's epoch.
    ///
    /// No monotonic clock that counts from boot or from process start gets
    /// there. An instant beyond it is a unit mix-up
    /// (`Ticks::from_secs(milliseconds)` saturates) or a value that was
    /// never set, and a [`crate::Tunnel`] or [`crate::Device`] given one
    /// treats it as it treats a clock that goes backwards: for that call,
    /// no time has passed. Taken at face value it would make every
    /// deadline due at once and for ever — sessions wiped, and something
    /// to send on every `poll`.
    pub const MAX: Self = Self(u64::MAX >> 1);

    /// Construct from nanoseconds since the caller's epoch.
    #[must_use]
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    /// Construct from seconds since the caller's epoch.
    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self(secs.saturating_mul(1_000_000_000))
    }

    /// Nanoseconds since the caller's epoch.
    #[must_use]
    pub const fn nanos(self) -> u64 {
        self.0
    }

    /// This instant plus a duration in nanoseconds (saturating).
    #[must_use]
    pub const fn add_nanos(self, nanos: u64) -> Self {
        Self(self.0.saturating_add(nanos))
    }

    /// Nanoseconds elapsed from `earlier` to `self`; zero if `earlier` is
    /// in the future (saturating).
    #[must_use]
    pub const fn since(self, earlier: Self) -> u64 {
        self.0.saturating_sub(earlier.0)
    }

    /// The earlier of two instants.
    #[must_use]
    pub const fn min(self, other: Self) -> Self {
        if self.0 <= other.0 { self } else { other }
    }

    /// The later of two instants.
    #[must_use]
    pub const fn max(self, other: Self) -> Self {
        if self.0 >= other.0 { self } else { other }
    }

    /// What a caller's `now` counts as, given the latest instant seen so
    /// far: itself, unless it is earlier than that or beyond
    /// [`Ticks::MAX`] — then time has not moved.
    #[must_use]
    pub(crate) const fn following(self, latest: Self) -> Self {
        if self.0 < latest.0 || self.0 > Self::MAX.0 {
            latest
        } else {
            self
        }
    }
}

/// One nanosecond-resolution second.
const NANOS_PER_SEC: u64 = 1_000_000_000;

/// A wall-clock anchor: "at monotonic instant [`Ticks`] `at`, the Unix
/// clock read `unix_secs`.`unix_nanos`".
///
/// Read the wall clock once, when the [`crate::Device`] is created, and
/// hand it over in this form. Handshake timestamps are then computed as
/// `anchor + (now − at)` from the monotonic clock alone.
///
/// A platform that boots without a real-time clock can re-anchor after it
/// learns the time ([`crate::Device::set_wall_clock`],
/// [`crate::Tunnel::set_wall_clock`]); outbound timestamps are ratcheted, so
/// re-anchoring to an earlier time never makes them decrease within a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WallClock {
    at: Ticks,
    unix_secs: u64,
    unix_nanos: u32,
}

impl WallClock {
    /// Anchor the wall clock: at monotonic instant `at` the Unix clock read
    /// `unix_secs` seconds and `unix_nanos` nanoseconds. `unix_nanos` is
    /// clamped to `999_999_999`.
    #[must_use]
    pub const fn new(at: Ticks, unix_secs: u64, unix_nanos: u32) -> Self {
        let unix_nanos = if unix_nanos > 999_999_999 {
            999_999_999
        } else {
            unix_nanos
        };
        Self {
            at,
            unix_secs,
            unix_nanos,
        }
    }

    /// The Unix time `(seconds, nanoseconds)` this anchor implies for the
    /// monotonic instant `now`. Instants before the anchor read as the
    /// anchor itself; everything saturates.
    #[must_use]
    pub const fn unix_at(&self, now: Ticks) -> (u64, u32) {
        let elapsed = now.since(self.at);
        let nanos = (self.unix_nanos as u64).saturating_add(elapsed % NANOS_PER_SEC);
        let carry = nanos / NANOS_PER_SEC;
        let secs = self
            .unix_secs
            .saturating_add(elapsed / NANOS_PER_SEC)
            .saturating_add(carry);
        // `nanos % NANOS_PER_SEC` is below 10^9 and so fits a `u32`.
        (secs, (nanos % NANOS_PER_SEC) as u32)
    }

    /// The TAI64N timestamp for the monotonic instant `now`.
    #[must_use]
    pub const fn tai64n(&self, now: Ticks) -> Tai64N {
        let (secs, nanos) = self.unix_at(now);
        Tai64N::from_unix(secs, nanos)
    }
}

/// A TAI64N timestamp (whitepaper §5.1): 8 bytes big-endian seconds since
/// the TAI epoch, then 4 bytes big-endian nanoseconds.
///
/// Big-endian layout means plain lexicographic byte comparison orders
/// timestamps chronologically; the derived `Ord` on the inner array does
/// exactly that. Timestamps are not secret, so a variable-time comparison
/// is fine.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tai64N([u8; 12]);

/// TAI64 label of the Unix epoch as used by existing WireGuard
/// implementations (`2^62 + 10`).
const TAI64_UNIX_BASE: u64 = 0x4000_0000_0000_000a;

/// The whitepaper (§5.1) permits truncating 24 bits of the nanoseconds to
/// avoid leaking fine-grained clock readings; in-tree implementations do,
/// and so do we.
const NANOS_WHITENER_MASK: u32 = !0x00ff_ffff;

impl Tai64N {
    /// Build the (whitened) TAI64N timestamp for a Unix wall-clock reading.
    #[must_use]
    pub const fn from_unix(unix_secs: u64, unix_nanos: u32) -> Self {
        let secs = TAI64_UNIX_BASE.saturating_add(unix_secs);
        let nanos = (unix_nanos & NANOS_WHITENER_MASK) % 1_000_000_000;
        let [s0, s1, s2, s3, s4, s5, s6, s7] = secs.to_be_bytes();
        let [n0, n1, n2, n3] = nanos.to_be_bytes();
        Self([s0, s1, s2, s3, s4, s5, s6, s7, n0, n1, n2, n3])
    }

    /// Interpret 12 raw bytes as a TAI64N timestamp.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    /// The wire encoding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }

    /// The smallest TAI64N strictly greater than `self` (96-bit big-endian
    /// increment, saturating at all-ones). Used to ratchet outbound
    /// initiation timestamps so that the peer never sees one repeat or go
    /// backwards — which it would reject as
    /// [`crate::DropReason::ReplayedTimestamp`]. The increment lands in the
    /// low (whitened-away) nanosecond bits, so it leaks nothing the
    /// previous timestamp did not.
    #[must_use]
    pub fn tick(self) -> Self {
        let mut bytes = self.0;
        for b in bytes.iter_mut().rev() {
            let (next, carry) = b.overflowing_add(1);
            *b = next;
            if !carry {
                return Self(bytes);
            }
        }
        Self([0xff; 12]) // saturate (unreachable before year ~10^11)
    }
}

impl fmt::Debug for Tai64N {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tai64N({:02x?})", self.0)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
    use super::*;

    #[test]
    fn ticks_arithmetic_saturates() {
        assert_eq!(Ticks::from_nanos(u64::MAX).add_nanos(1).nanos(), u64::MAX);
        assert_eq!(Ticks::from_secs(u64::MAX).nanos(), u64::MAX);
        assert_eq!(Ticks::from_nanos(5).since(Ticks::from_nanos(9)), 0);
        assert_eq!(Ticks::from_nanos(9).since(Ticks::from_nanos(5)), 4);
        assert_eq!(
            Ticks::from_nanos(3).min(Ticks::from_nanos(7)),
            Ticks::from_nanos(3)
        );
    }

    #[test]
    fn tai64n_layout_and_base() {
        // Unix epoch exactly.
        let t = Tai64N::from_unix(0, 0);
        assert_eq!(
            t.as_bytes(),
            &[0x40, 0, 0, 0, 0, 0, 0, 0x0a, 0, 0, 0, 0],
            "TAI64 label of the Unix epoch must be 2^62 + 10"
        );
        // Seconds land in the first 8 bytes, big-endian.
        let t = Tai64N::from_unix(1, 0);
        assert_eq!(&t.as_bytes()[..8], &[0x40, 0, 0, 0, 0, 0, 0, 0x0b]);
    }

    #[test]
    fn tai64n_orders_chronologically() {
        let a = Tai64N::from_unix(100, 0);
        let b = Tai64N::from_unix(100, 999_999_999);
        let c = Tai64N::from_unix(101, 0);
        assert!(a < b && b < c);
        // Equal after whitening: nanos differing only in the low 24 bits
        // compare equal -- callers (the handshake) rely on strict "greater"
        // so this must be Equal, not Less.
        let d = Tai64N::from_unix(100, 0x0100_0000);
        let e = Tai64N::from_unix(100, 0x01ff_ffff);
        assert_eq!(d, e);
    }

    #[test]
    fn tai64n_whitening_truncates_low_24_bits() {
        let t = Tai64N::from_unix(0, 0x0123_4567);
        assert_eq!(&t.as_bytes()[8..], &[0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn tai64n_never_panics_on_extreme_inputs() {
        let _ = Tai64N::from_unix(u64::MAX, u32::MAX);
        let w = WallClock::new(Ticks::from_nanos(u64::MAX), u64::MAX, u32::MAX);
        let _ = w.tai64n(Ticks::from_nanos(u64::MAX));
        let _ = w.tai64n(Ticks::ZERO);
        assert_eq!(
            WallClock::new(Ticks::ZERO, 0, u32::MAX).unix_at(Ticks::ZERO),
            (0, 999_999_999)
        );
    }

    #[test]
    fn wall_clock_follows_the_monotonic_clock() {
        let w = WallClock::new(Ticks::from_secs(10), 1_700_000_000, 900_000_000);
        // At the anchor.
        assert_eq!(
            w.unix_at(Ticks::from_secs(10)),
            (1_700_000_000, 900_000_000)
        );
        // Before the anchor: reads as the anchor (never earlier).
        assert_eq!(w.unix_at(Ticks::ZERO), (1_700_000_000, 900_000_000));
        // Sub-second carry into the seconds field.
        assert_eq!(
            w.unix_at(Ticks::from_nanos(10 * 1_000_000_000 + 200_000_000)),
            (1_700_000_001, 100_000_000)
        );
        // Whole seconds.
        assert_eq!(
            w.unix_at(Ticks::from_secs(70)),
            (1_700_000_060, 900_000_000)
        );
        // Timestamps are non-decreasing in `now`.
        let mut last = w.tai64n(Ticks::ZERO);
        for step in 0..2_000u64 {
            let t = w.tai64n(Ticks::from_nanos(step * 7_919_000));
            assert!(t >= last, "timestamp went backwards at step {step}");
            last = t;
        }
        // And strictly increasing across whole seconds.
        assert!(w.tai64n(Ticks::from_secs(12)) > w.tai64n(Ticks::from_secs(11)));
    }

    #[test]
    fn tai64n_tick_is_strictly_greater_and_carries() {
        let t = Tai64N::from_unix(100, 0);
        assert!(t.tick() > t);
        // Carry across the nanos→seconds boundary.
        let edge = Tai64N::from_bytes([0, 0, 0, 0, 0, 0, 0, 7, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(
            edge.tick().as_bytes(),
            &[0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0]
        );
        // Saturates at the top instead of wrapping to zero.
        let max = Tai64N::from_bytes([0xff; 12]);
        assert_eq!(max.tick(), max);
    }
}
